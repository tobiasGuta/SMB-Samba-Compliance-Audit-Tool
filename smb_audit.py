#!/usr/bin/env python3

import argparse
import json
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30

# SMB 3.1.1 dialect constant (0x0311) — not exported by all impacket versions
try:
    from impacket.smb3structs import SMB2_DIALECT_311
except ImportError:
    SMB2_DIALECT_311 = 0x0311
from impacket.dcerpc.v5 import transport, samr, lsat, lsad, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import SessionError

from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel
from rich.syntax import Syntax

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_console = Console()

SMB_DIALECTS = {
    "SMBv1": SMB_DIALECT,
    "SMBv2": SMB2_DIALECT_002,
    "SMBv2.1": SMB2_DIALECT_21,
    "SMBv3": SMB2_DIALECT_30,
    "SMBv3.1.1": SMB2_DIALECT_311,
}

DEFAULT_BACKUP_REGEX = r'(?i).*\.(bak|sql|db|kdbx|config|xml|env|ps1|pem|key|pfx)$|^(id_rsa|web\.config|unattend\.xml)$'
DEFAULT_MAX_DOWNLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

USER_DISPLAY_THRESHOLD = 25  # print full user table up to this count

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

# ---------------------------------------------------------------------------
# CLI / Argparse
# ---------------------------------------------------------------------------


def build_argparser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="smb_audit",
        description=(
            "SMB/Samba Compliance & Audit Tool — enumerate shares, audit "
            "permissions, retrieve password policies, discover exposed backup "
            "files, and export structured reports."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s 192.168.1.10 -u admin -p Password1\n"
            "  %(prog)s 10.0.0.5 -u admin --hashes aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889\n"
            "  %(prog)s 10.0.0.5 --null-session --smb-version SMBv1\n"
            "  %(prog)s 10.0.0.5 -u admin -p Pass1 --spider --download --max-size 5242880 --json report.json\n"
        ),
    )

    # ── Target ────────────────────────────────────────────────────────────
    parser.add_argument(
        "target",
        help="IP address or hostname of the SMB target.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=445,
        help="SMB port (default: 445).",
    )

    # ── Authentication ────────────────────────────────────────────────────
    auth = parser.add_argument_group("authentication")
    auth.add_argument("-u", "--username", default="", help="Username for authentication.")
    auth.add_argument("-p", "--password", default="", help="Password for authentication.")
    auth.add_argument("-d", "--domain", default=".", help="Domain or workgroup (default: '.').")
    auth.add_argument(
        "--hashes",
        metavar="LMHASH:NTHASH",
        default=None,
        help="NTLM hash pair for pass-the-hash authentication (format LM:NT).",
    )
    auth.add_argument(
        "--null-session",
        action="store_true",
        default=False,
        help="Attempt a Null Session (anonymous) login.",
    )
    auth.add_argument(
        "--guest",
        action="store_true",
        default=False,
        help="Attempt Guest account login after primary auth fails.",
    )

    # ── Protocol ──────────────────────────────────────────────────────────
    proto = parser.add_argument_group("protocol options")
    proto.add_argument(
        "--smb-version",
        choices=list(SMB_DIALECTS.keys()),
        default=None,
        help="Force a specific SMB dialect for legacy compliance checks.",
    )
    proto.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Connection timeout in seconds (default: 10).",
    )

    # ── Audit scope ───────────────────────────────────────────────────────
    scope = parser.add_argument_group("audit scope")
    scope.add_argument(
        "--shares",
        action="store_true",
        default=False,
        help="Enumerate shares and audit read/write permissions.",
    )
    scope.add_argument(
        "--policy",
        action="store_true",
        default=False,
        help="Query domain/local password policy via SAMR/LSA.",
    )
    scope.add_argument(
        "--users",
        action="store_true",
        default=False,
        help="Enumerate local users and groups via SAMR.",
    )
    scope.add_argument(
        "--sessions",
        action="store_true",
        default=False,
        help="Enumerate active SMB sessions on the target (requires admin).",
    )
    scope.add_argument(
        "--vulns",
        action="store_true",
        default=False,
        help="Run heuristic vulnerability checks (signing, legacy dialects).",
    )
    scope.add_argument(
        "--all",
        action="store_true",
        default=False,
        help="Run all audit modules (shares, policy, users, sessions, spider, vulns).",
    )

    # ── Backup discovery ──────────────────────────────────────────────────
    spider = parser.add_argument_group("backup discovery (spider)")
    spider.add_argument(
        "--spider",
        action="store_true",
        default=False,
        help="Recursively spider accessible shares for backup/sensitive files.",
    )
    spider.add_argument(
        "--spider-regex",
        default=None,
        help=(
            "Regex pattern to match sensitive filenames. "
            "If omitted, a built-in high-value file signature set is used."
        ),
    )
    spider.add_argument(
        "--spider-depth",
        type=int,
        default=5,
        help="Maximum recursion depth for spidering (default: 5).",
    )
    spider.add_argument(
        "--spider-exclude",
        nargs="*",
        default=["IPC$"],
        help="Shares to skip during spidering (default: IPC$).",
    )
    spider.add_argument(
        "--download",
        action="store_true",
        default=False,
        help="Download matched files that are under --max-size bytes.",
    )
    spider.add_argument(
        "--max-size",
        type=int,
        default=DEFAULT_MAX_DOWNLOAD_SIZE,
        help=f"Max file size in bytes to auto-download (default: {DEFAULT_MAX_DOWNLOAD_SIZE}).",
    )
    spider.add_argument(
        "--download-dir",
        default="./loot",
        help="Local directory to store downloaded files (default: ./loot).",
    )
    spider.add_argument(
        "--list-files",
        action="store_true",
        default=False,
        help="List ALL files found while spidering, not only sensitive matches.",
    )

    # ── File operations ───────────────────────────────────────────────────
    fileops = parser.add_argument_group("file operations")
    fileops.add_argument(
        "--cat",
        metavar="SHARE/PATH",
        default=None,
        help=(
            "View a remote file in the terminal without downloading. "
            "Format: SHARE_NAME/path/to/file  (e.g. Data/config/web.config)."
        ),
    )

    # ── Performance ───────────────────────────────────────────────────────
    perf = parser.add_argument_group("performance")
    perf.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Number of threads for concurrent share auditing (default: 4).",
    )

    # ── Output ────────────────────────────────────────────────────────────
    output = parser.add_argument_group("output")
    output.add_argument(
        "--json",
        metavar="FILE",
        dest="json_file",
        default=None,
        help="Export all findings to a structured JSON file.",
    )
    output.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG).",
    )

    return parser


# ---------------------------------------------------------------------------
# Main Audit Class
# ---------------------------------------------------------------------------


class SMBAuditor:
    """Core audit engine that orchestrates connection, enumeration, and reporting."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.target: str = args.target
        self.port: int = args.port
        self.username: str = args.username
        self.password: str = args.password
        self.domain: str = args.domain
        self.lmhash: str = ""
        self.nthash: str = ""
        self.timeout: int = args.timeout

        if args.hashes:
            parts = args.hashes.split(":")
            if len(parts) == 2:
                self.lmhash, self.nthash = parts
            else:
                logging.error("Invalid hash format. Expected LMHASH:NTHASH.")
                sys.exit(1)

        self.conn: SMBConnection | None = None
        self.auth_method: str = "N/A"
        self._lock = threading.Lock()  # guards concurrent writes to findings

        # Collected findings for JSON export
        self.findings: dict = {
            "target": self.target,
            "port": self.port,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "auth_method": None,
            "smb_dialect": None,
            "security": {
                "dialect": None,
                "signing": None,
            },
            "shares": [],
            "password_policy": {},
            "users": [],
            "groups": [],
            "sessions": [],
            "spider_results": [],
            "all_files": [],
            "vulnerabilities": [],
        }

    # ── Connection & Authentication ───────────────────────────────────────

    def connect(self) -> SMBConnection:
        """Establish an SMB connection to the target, negotiating the requested dialect."""
        preferred = self.args.smb_version
        dialect_arg = SMB_DIALECTS.get(preferred) if preferred else None

        logging.info("Connecting to %s:%d …", self.target, self.port)

        try:
            if dialect_arg is not None:
                logging.info("Forcing dialect: %s", preferred)
                conn = SMBConnection(
                    self.target,
                    self.target,
                    sess_port=self.port,
                    preferredDialect=dialect_arg,
                    timeout=self.timeout,
                )
            else:
                conn = SMBConnection(
                    self.target,
                    self.target,
                    sess_port=self.port,
                    timeout=self.timeout,
                )
        except Exception as exc:
            logging.error("Connection failed: %s", exc)
            sys.exit(1)

        dialect_id = conn.getDialect()
        dialect_name = self._dialect_to_str(dialect_id)
        logging.info("Negotiated dialect: %s (0x%04x)", dialect_name, dialect_id)
        self.findings["smb_dialect"] = dialect_name
        self.findings["security"]["dialect"] = dialect_name

        # ── SMB Signing detection ─────────────────────────────────────────
        signing_status = self._detect_signing(conn)
        self.findings["security"]["signing"] = signing_status
        logging.info("SMB Signing: %s", signing_status)

        self.conn = conn
        return conn

    def authenticate(self) -> bool:
        """Authenticate using password/hash, null session, or guest — in that order."""
        if self.conn is None:
            logging.error("No active connection. Call connect() first.")
            return False

        # --- Password or hash ---
        if self.username and (self.password or self.nthash):
            try:
                self.conn.login(
                    self.username,
                    self.password,
                    domain=self.domain,
                    lmhash=self.lmhash,
                    nthash=self.nthash,
                )
                method = "NTLM-Hash" if self.nthash else "Password"
                logging.info("Authenticated as %s\\%s via %s", self.domain, self.username, method)
                self.auth_method = method
                self.findings["auth_method"] = method
                return True
            except Exception as exc:
                logging.warning("Credential auth failed: %s", exc)

        # --- Null Session ---
        if self.args.null_session:
            try:
                self.conn.login("", "", domain="")
                logging.info("Null Session established.")
                self.auth_method = "Null-Session"
                self.findings["auth_method"] = "Null-Session"
                return True
            except Exception as exc:
                logging.warning("Null Session failed: %s", exc)

        # --- Guest fallback ---
        if self.args.guest:
            try:
                self.conn.login("Guest", "", domain=self.domain)
                logging.info("Guest account login succeeded.")
                self.auth_method = "Guest"
                self.findings["auth_method"] = "Guest"
                return True
            except Exception as exc:
                logging.warning("Guest login failed: %s", exc)

        logging.error("All authentication methods exhausted.")
        return False

    # ── Share & Permissions Audit ─────────────────────────────────────────

    def enum_shares(self) -> list[dict]:
        """Enumerate all SMB shares and test read/write access on each."""
        results: list[dict] = []

        # --- Bind to \srvsvc ---
        rpctransport = transport.SMBTransport(
            self.target,
            self.port,
            r"\srvsvc",
            smb_connection=self.conn,
        )
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrShareEnum(dce, 1)  # info-level 1 for remarks
        except Exception as exc:
            logging.error("Failed to enumerate shares via SRVSVC: %s", exc)
            return results
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass

        share_type_map = {
            srvs.STYPE_DISKTREE: "Disk",
            srvs.STYPE_PRINTQ: "Printer",
            srvs.STYPE_DEVICE: "Device",
            srvs.STYPE_IPC: "IPC",
            srvs.STYPE_CLUSTER_FS: "ClusterFS",
            srvs.STYPE_CLUSTER_SOFS: "ClusterSOFS",
            srvs.STYPE_CLUSTER_DFS: "ClusterDFS",
        }

        for share_info in resp["InfoStruct"]["ShareInfo"]["Level1"]["Buffer"]:
            name = share_info["shi1_netname"][:-1]  # strip null terminator
            raw_type = share_info["shi1_type"]
            remark = share_info["shi1_remark"][:-1]

            # Mask off the STYPE_SPECIAL (0x80000000) and STYPE_TEMPORARY bits
            base_type = raw_type & 0x0FFFFFFF
            type_str = share_type_map.get(base_type, f"Unknown(0x{raw_type:08x})")
            if raw_type & 0x80000000:
                type_str += " [Special/Admin]"

            readable = self._test_share_read(name)
            writable = self._test_share_write(name) if readable else False

            entry = {
                "name": name,
                "type": type_str,
                "remark": remark,
                "read": readable,
                "write": writable,
            }
            results.append(entry)

            flag_r = "R" if readable else "-"
            flag_w = "W" if writable else "-"
            logging.info("  %-20s  [%s%s]  %s  %s", name, flag_r, flag_w, type_str, remark)

        self.findings["shares"] = results
        return results

    def _test_share_read(self, share_name: str) -> bool:
        """List the share root to check read access."""
        try:
            self.conn.listPath(share_name, "*")
            return True
        except SessionError as exc:
            logging.debug("Read test on '%s' denied: %s", share_name, exc)
            return False
        except Exception as exc:
            logging.debug("Read test on '%s' error: %s", share_name, exc)
            return False

    def _test_share_write(self, share_name: str) -> bool:
        """Create and delete a temp dir on the share to check write access."""
        test_dir = "audit_test_dir"
        created = False
        try:
            self.conn.createDirectory(share_name, test_dir)
            created = True
            return True
        except SessionError as exc:
            logging.debug("Write test on '%s' denied: %s", share_name, exc)
            return False
        except Exception as exc:
            logging.debug("Write test on '%s' error: %s", share_name, exc)
            return False
        finally:
            if created:
                try:
                    self.conn.deleteDirectory(share_name, test_dir)
                except Exception:
                    logging.debug("Could not clean up test dir on '%s'", share_name)

    # ── SAMR Helpers ──────────────────────────────────────────────────────

    def _open_samr_domain(self):
        """Bind to SAMR, connect, and open the target domain. Returns (dce, server_handle, domain_handle, domain_name)."""
        rpctransport = transport.SMBTransport(
            self.target,
            self.port,
            r"\samr",
            smb_connection=self.conn,
        )
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        # Connect to SAM
        resp = samr.hSamrConnect(dce)
        server_handle = resp["ServerHandle"]

        # Enumerate domains — pick the first non-Builtin one
        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = [e["Name"] for e in resp["Buffer"]["Buffer"]]
        logging.debug("SAMR domains found: %s", domains)

        domain_name = "Builtin"
        for d in domains:
            if d.upper() != "BUILTIN":
                domain_name = d
                break

        # Look up domain SID and open it
        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
        domain_sid = resp["DomainId"]

        resp = samr.hSamrOpenDomain(
            dce, server_handle, domainId=domain_sid,
            desiredAccess=samr.MAXIMUM_ALLOWED,
        )
        domain_handle = resp["DomainHandle"]

        return dce, server_handle, domain_handle, domain_name

    @staticmethod
    def _close_samr_handles(dce, *handles) -> None:
        """Close SAMR handles and disconnect the DCE pipe."""
        for h in handles:
            try:
                samr.hSamrCloseHandle(dce, h)
            except Exception:
                pass
        try:
            dce.disconnect()
        except Exception:
            pass

    @staticmethod
    def _large_int_to_timedelta(large_int) -> timedelta | None:
        """Convert a LARGE_INTEGER (100-ns intervals, negative) to timedelta."""
        val = large_int["LowPart"] + (large_int["HighPart"] << 32)
        if val == 0 or val == 0x7FFFFFFFFFFFFFFF:
            return None
        # Value is stored as negative 100-nanosecond intervals
        seconds = abs(val) / 1e7
        return timedelta(seconds=seconds)

    # ── Password Policy (SAMR / LSA) ─────────────────────────────────────

    def get_password_policy(self) -> dict:
        """Query domain/local password policy (length, complexity, lockout) via SAMR."""
        dce = server_handle = domain_handle = None
        policy: dict = {}

        try:
            dce, server_handle, domain_handle, domain_name = self._open_samr_domain()
            logging.info("Querying password policy for domain '%s' …", domain_name)

            # --- Password info (class 1) ---
            resp = samr.hSamrQueryInformationDomain(
                dce, domain_handle,
                domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation,
            )
            pw_info = resp["Buffer"]["Password"]

            min_len = pw_info["MinPasswordLength"]
            history_len = pw_info["PasswordHistoryLength"]
            pw_properties = pw_info["PasswordProperties"]

            max_age_td = self._large_int_to_timedelta(pw_info["MaxPasswordAge"])
            min_age_td = self._large_int_to_timedelta(pw_info["MinPasswordAge"])

            complexity_required = bool(pw_properties & 0x01)  # DOMAIN_PASSWORD_COMPLEX

            policy["domain"] = domain_name
            policy["min_password_length"] = min_len
            policy["password_history_length"] = history_len
            policy["complexity_required"] = complexity_required
            policy["max_password_age"] = str(max_age_td) if max_age_td else "Unlimited"
            policy["min_password_age"] = str(min_age_td) if min_age_td else "None"

            # --- Lockout info (class 12) ---
            resp = samr.hSamrQueryInformationDomain(
                dce, domain_handle,
                domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation,
            )
            lockout_info = resp["Buffer"]["Lockout"]

            lockout_threshold = lockout_info["LockoutThreshold"]
            lockout_duration_td = self._large_int_to_timedelta(lockout_info["LockoutDuration"])
            lockout_window_td = self._large_int_to_timedelta(lockout_info["LockoutObservationWindow"])

            policy["lockout_threshold"] = lockout_threshold
            policy["lockout_duration"] = str(lockout_duration_td) if lockout_duration_td else "Until Admin Unlock"
            policy["lockout_observation_window"] = str(lockout_window_td) if lockout_window_td else "N/A"

            logging.info("  Min length: %d | History: %d | Complexity: %s",
                         min_len, history_len, complexity_required)
            logging.info("  Lockout threshold: %d | Duration: %s | Window: %s",
                         lockout_threshold,
                         policy["lockout_duration"],
                         policy["lockout_observation_window"])

        except Exception as exc:
            logging.error("Password policy query failed: %s", exc)
        finally:
            if dce is not None:
                handles = [h for h in (domain_handle, server_handle) if h is not None]
                self._close_samr_handles(dce, *handles)

        self.findings["password_policy"] = policy
        return policy

    # ── User & Group Enumeration (SAMR) ───────────────────────────────────

    def enum_users(self) -> list[dict]:
        """Enumerate local user accounts via SAMR, returning rid/name/status."""
        dce = server_handle = domain_handle = None
        users: list[dict] = []

        try:
            dce, server_handle, domain_handle, domain_name = self._open_samr_domain()
            logging.info("Enumerating users in domain '%s' …", domain_name)

            # user_account_control filter: 0 = all users
            enum_status = samr.STATUS_MORE_ENTRIES
            enumeration_context = 0

            while enum_status == samr.STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(
                        dce, domain_handle,
                        userAccountControl=0,
                        enumerationContext=enumeration_context,
                        preferedMaximumLength=0xFFFF,
                    )
                except samr.DCERPCSessionError as exc:
                    # STATUS_MORE_ENTRIES may come as an exception in some builds
                    if exc.get_error_code() == samr.STATUS_MORE_ENTRIES:
                        resp = exc.get_packet()
                    else:
                        raise

                enum_status = resp["ErrorCode"]
                enumeration_context = resp["EnumerationContext"]

                for entry in resp["Buffer"]["Buffer"]:
                    rid = entry["RelativeId"]
                    name = entry["Name"]

                    # Open each user to read account flags
                    status = "active"
                    try:
                        user_resp = samr.hSamrOpenUser(
                            dce, domain_handle, samr.MAXIMUM_ALLOWED, rid,
                        )
                        user_handle = user_resp["UserHandle"]
                        try:
                            info_resp = samr.hSamrQueryInformationUser(
                                dce, user_handle,
                                samr.USER_INFORMATION_CLASS.UserControlInformation,
                            )
                            uac = info_resp["Buffer"]["Control"]["UserAccountControl"]
                            if uac & samr.USER_ACCOUNT_DISABLED:
                                status = "disabled"
                        finally:
                            samr.hSamrCloseHandle(dce, user_handle)
                    except Exception as exc:
                        logging.debug("Could not query UAC for RID %d: %s", rid, exc)

                    record = {"rid": rid, "name": name, "status": status}
                    users.append(record)
                    logging.info("  RID %-6d  %-30s  %s", rid, name, status)

        except Exception as exc:
            logging.error("User enumeration failed: %s", exc)
        finally:
            if dce is not None:
                handles = [h for h in (domain_handle, server_handle) if h is not None]
                self._close_samr_handles(dce, *handles)

        self.findings["users"] = users
        return users

    def enum_groups(self) -> list[dict]:
        """Enumerate local groups/aliases and their members via SAMR."""
        dce = server_handle = domain_handle = None
        groups: list[dict] = []

        try:
            dce, server_handle, domain_handle, domain_name = self._open_samr_domain()
            logging.info("Enumerating groups/aliases in domain '%s' …", domain_name)

            enum_status = samr.STATUS_MORE_ENTRIES
            enumeration_context = 0

            while enum_status == samr.STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateAliasesInDomain(
                        dce, domain_handle,
                        enumerationContext=enumeration_context,
                        preferedMaximumLength=0xFFFF,
                    )
                except samr.DCERPCSessionError as exc:
                    if exc.get_error_code() == samr.STATUS_MORE_ENTRIES:
                        resp = exc.get_packet()
                    else:
                        raise

                enum_status = resp["ErrorCode"]
                enumeration_context = resp["EnumerationContext"]

                for entry in resp["Buffer"]["Buffer"]:
                    rid = entry["RelativeId"]
                    name = entry["Name"]

                    # Resolve group members
                    members: list[str] = []
                    try:
                        alias_resp = samr.hSamrOpenAlias(
                            dce, domain_handle, samr.MAXIMUM_ALLOWED, rid,
                        )
                        alias_handle = alias_resp["AliasHandle"]
                        try:
                            member_resp = samr.hSamrGetMembersInAlias(dce, alias_handle)
                            for sid in member_resp["Members"]["Sids"]:
                                members.append(sid["SidPointer"].formatCanonical())
                        finally:
                            samr.hSamrCloseHandle(dce, alias_handle)
                    except Exception as exc:
                        logging.debug("Could not enumerate members for alias RID %d: %s", rid, exc)

                    record = {"rid": rid, "name": name, "members": members}
                    groups.append(record)
                    logging.info("  RID %-6d  %-30s  members: %d", rid, name, len(members))

        except Exception as exc:
            logging.error("Group enumeration failed: %s", exc)
        finally:
            if dce is not None:
                handles = [h for h in (domain_handle, server_handle) if h is not None]
                self._close_samr_handles(dce, *handles)

        self.findings["groups"] = groups
        return groups

    # ── Active Session Audit ──────────────────────────────────────────────

    def enum_sessions(self) -> list[dict]:
        """Enumerate active SMB sessions via SRVSVC (requires admin)."""
        sessions: list[dict] = []

        rpctransport = transport.SMBTransport(
            self.target,
            self.port,
            r"\srvsvc",
            smb_connection=self.conn,
        )
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)

            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

            for session in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
                username = session["sesi10_username"][:-1]   # strip null
                source = session["sesi10_cname"][:-1]
                active_time = session["sesi10_time"]
                idle_time = session["sesi10_idle_time"]

                record = {
                    "username": username,
                    "source": source,
                    "active_time": active_time,
                    "idle_time": idle_time,
                }
                sessions.append(record)
                logging.info(
                    "  Session: %-20s from %-25s active %ds idle %ds",
                    username, source, active_time, idle_time,
                )

        except SessionError as exc:
            error_code = exc.getErrorCode()
            # STATUS_ACCESS_DENIED = 0xC0000022
            if error_code == 0xC0000022:
                logging.warning(
                    "Session enumeration denied — administrative privileges required."
                )
                sessions.append({
                    "username": None,
                    "source": None,
                    "active_time": None,
                    "idle_time": None,
                    "error": "ACCESS_DENIED",
                })
            else:
                logging.error("Session enumeration failed: %s", exc)
                sessions.append({
                    "username": None,
                    "source": None,
                    "active_time": None,
                    "idle_time": None,
                    "error": str(exc),
                })
        except Exception as exc:
            logging.error("Session enumeration failed: %s", exc)
        finally:
            try:
                dce.disconnect()
            except Exception:
                pass

        self.findings["sessions"] = sessions
        return sessions

    # ── Vulnerability Heuristics ──────────────────────────────────────────

    def check_vulnerabilities(self) -> list[dict]:
        """Flag known SMB weaknesses based on dialect and signing status."""
        vulns: list[dict] = []
        sec = self.findings.get("security", {})
        dialect = sec.get("dialect") or self.findings.get("smb_dialect") or ""
        signing = sec.get("signing") or ""

        # Check 1 — NTLM Relay (SMB Signing not required)
        if signing in ("Disabled", "Supported"):
            vulns.append({
                "vulnerability": "NTLM Relay — SMB Signing Not Required",
                "severity": "High",
                "details": (
                    f"SMB Signing is '{signing}' on this host. An attacker on the "
                    "local network can relay NTLM authentication to this target "
                    "and execute commands or access resources as the relayed user. "
                    "Remediation: enforce SMB signing via Group Policy "
                    "(RequireSecuritySignature = 1)."
                ),
            })
            logging.info("VULN: NTLM Relay — signing is '%s'", signing)

        # Check 2 — MS17-010 / EternalBlue (SMBv1)
        if dialect == "SMBv1":
            vulns.append({
                "vulnerability": "MS17-010 / EternalBlue (SMBv1)",
                "severity": "Critical",
                "details": (
                    "The target negotiated SMBv1, a deprecated protocol with known "
                    "remote code execution vulnerabilities (EternalBlue / WannaCry). "
                    "Even if patched, SMBv1 should be disabled entirely. "
                    "Remediation: disable SMBv1 via "
                    "'Set-SmbServerConfiguration -EnableSMB1Protocol $false' "
                    "or the Windows Features panel."
                ),
            })
            logging.info("VULN: SMBv1 detected — MS17-010 / EternalBlue risk")

        # Check 3 — CVE-2020-0796 / SMBGhost (SMBv3.1.1)
        if dialect == "SMBv3.1.1":
            vulns.append({
                "vulnerability": "CVE-2020-0796 / SMBGhost (SMBv3.1.1)",
                "severity": "Info",
                "details": (
                    "The target negotiated SMBv3.1.1 which is affected by "
                    "CVE-2020-0796 (SMBGhost) if compression is enabled and "
                    "the host is unpatched (Windows 10 v1903/v1909, Server v1903/v1909). "
                    "Verify the patch status of KB4551762. "
                    "Remediation: apply the patch or disable SMBv3 compression via "
                    "'Set-ItemProperty -Path "
                    "\"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer"
                    "\\Parameters\" DisableCompression -Type DWORD -Value 1'."
                ),
            })
            logging.info("VULN: SMBv3.1.1 detected — verify CVE-2020-0796 patch")

        self.findings["vulnerabilities"] = vulns
        return vulns

    # ── Backup Discovery (Spider) ─────────────────────────────────────────

    def spider_shares(self) -> list[dict]:
        """Spider accessible shares for sensitive/backup files matching a regex."""
        # Determine regex — user-supplied or built-in default
        user_regex = self.args.spider_regex
        using_default = user_regex is None
        pattern_str = DEFAULT_BACKUP_REGEX if using_default else user_regex

        try:
            regex = re.compile(pattern_str)
        except re.error as exc:
            logging.error("Invalid spider regex: %s", exc)
            return []

        if using_default:
            logging.info("Using default high-value file signatures for spidering.")
        else:
            logging.info("Using custom spider regex: %s", pattern_str)

        self.findings["using_default_regex"] = using_default

        # Determine which shares are readable and not excluded
        exclude = {s.upper() for s in (self.args.spider_exclude or [])}

        # If shares haven't been enumerated yet, do it now so we know what
        # is readable.
        if not self.findings["shares"]:
            self.enum_shares()

        readable = [
            s["name"]
            for s in self.findings["shares"]
            if s["read"] and s["name"].upper() not in exclude
        ]

        if not readable:
            logging.warning("No readable shares to spider.")
            return []

        logging.info("Spidering %d share(s): %s", len(readable), ", ".join(readable))
        max_depth = self.args.spider_depth

        all_matches: list[dict] = []

        if self.args.threads > 1 and len(readable) > 1:
            all_matches = self.run_share_audit_threaded(readable, regex, max_depth)
        else:
            for share in readable:
                hits = self._spider_directory(share, "/", regex, max_depth)
                all_matches.extend(hits)

        self.findings["spider_results"] = all_matches
        logging.info("Spider complete — %d file(s) matched.", len(all_matches))
        if getattr(self.args, "list_files", False):
            logging.info("Total files catalogued: %d", len(self.findings["all_files"]))
        return all_matches

    def _spider_directory(
        self, share_name: str, path: str, regex: re.Pattern, depth: int
    ) -> list[dict]:
        """Recursively walk a directory, collecting files that match the regex."""
        matches: list[dict] = []

        if depth <= 0:
            return matches

        search_path = path.rstrip("/") + "/*" if path != "/" else "/*"

        try:
            entries = self.conn.listPath(share_name, search_path)
        except SessionError as exc:
            logging.debug("Cannot list '%s' on '%s': %s", path, share_name, exc)
            return matches
        except Exception as exc:
            logging.debug("Error listing '%s' on '%s': %s", path, share_name, exc)
            return matches

        for entry in entries:
            filename = entry.get_longname()

        # Skip . and .. to prevent infinite recursion
            if filename in (".", ".."):
                continue

            if path == "/":
                full_path = f"/{filename}"
            else:
                full_path = f"{path.rstrip('/')}/{filename}"

            is_dir = entry.is_directory()

            if is_dir:
                # Recurse into subdirectory
                sub_matches = self._spider_directory(
                    share_name, full_path, regex, depth - 1
                )
                matches.extend(sub_matches)
            else:
                file_size = entry.get_filesize()

                # Track every file when --list-files is active
                if getattr(self.args, "list_files", False):
                    file_record = {
                        "share": share_name,
                        "path": full_path,
                        "size": file_size,
                    }
                    with self._lock:
                        self.findings["all_files"].append(file_record)

                if regex.search(filename):
                    downloaded = False
                    local_path = None

                    if (
                        self.args.download
                        and file_size <= self.args.max_size
                    ):
                        local_path = self._download_file(
                            share_name, full_path, self.args.download_dir
                        )
                        downloaded = local_path is not None

                    record = {
                        "share": share_name,
                        "path": full_path,
                        "size": file_size,
                        "downloaded": downloaded,
                        "local_path": local_path,
                    }
                    matches.append(record)

                    dl_tag = " [SAVED]" if downloaded else ""
                    logging.info(
                        "  MATCH  \\\\%s%s  (%d bytes)%s",
                        share_name, full_path, file_size, dl_tag,
                    )

        return matches

    def _download_file(self, share_name: str, remote_path: str, local_dir: str) -> str | None:
        """Download a file from a share, replicating the remote dir structure locally."""
        # Build local path: <download_dir>/<share>/<remote dirs>/<file>
        relative = remote_path.lstrip("/").replace("/", os.sep)
        dest = os.path.join(local_dir, share_name, relative)
        dest_dir = os.path.dirname(dest)

        try:
            os.makedirs(dest_dir, exist_ok=True)
        except OSError as exc:
            logging.error("Cannot create local directory '%s': %s", dest_dir, exc)
            return None

        # Convert forward slashes to backslashes for the SMB wire path
        wire_path = remote_path.replace("/", "\\")

        try:
            with open(dest, "wb") as fh:
                self.conn.getFile(share_name, wire_path, fh.write)
            logging.debug("Downloaded \\\\%s%s → %s", share_name, remote_path, dest)
            return os.path.abspath(dest)
        except SessionError as exc:
            error_code = exc.getErrorCode()
            # STATUS_SHARING_VIOLATION = 0xC0000043
            if error_code == 0xC0000043:
                logging.warning(
                    "Sharing violation (file in use): \\\\%s%s — skipping download.",
                    share_name, remote_path,
                )
            else:
                logging.warning(
                    "Download failed for \\\\%s%s: %s",
                    share_name, remote_path, exc,
                )
            # Clean up partial file
            try:
                os.remove(dest)
            except OSError:
                pass
            return None
        except Exception as exc:
            logging.warning(
                "Download failed for \\\\%s%s: %s",
                share_name, remote_path, exc,
            )
            try:
                os.remove(dest)
            except OSError:
                pass
            return None

    # ── Threaded Orchestration ────────────────────────────────────────────

    def run_share_audit_threaded(
        self,
        share_names: list[str],
        regex: re.Pattern,
        max_depth: int,
    ) -> list[dict]:
        """Spider multiple shares concurrently using a thread pool."""
        all_matches: list[dict] = []

        with ThreadPoolExecutor(max_workers=self.args.threads) as pool:
            future_to_share = {
                pool.submit(self._spider_directory, share, "/", regex, max_depth): share
                for share in share_names
            }

            for future in as_completed(future_to_share):
                share = future_to_share[future]
                try:
                    hits = future.result()
                    with self._lock:
                        all_matches.extend(hits)
                    logging.info(
                        "Thread finished spidering '%s' — %d match(es).",
                        share, len(hits),
                    )
                except Exception as exc:
                    logging.error("Thread for share '%s' failed: %s", share, exc)

        return all_matches

    # ── Output / Reporting ────────────────────────────────────────────────

    def print_findings(self) -> None:
        """Print a rich-formatted summary of all collected findings to stdout."""
        f = self.findings
        c = _console

        # ── Header Panel ──────────────────────────────────────────────────
        auth = f.get("auth_method") or "N/A"
        sec = f.get("security", {})
        dialect = sec.get("dialect") or f.get("smb_dialect") or "N/A"
        signing = sec.get("signing") or "N/A"
        auth_ok = auth not in ("N/A", None)
        border_style = "green" if auth_ok else "red"

        # Dialect annotation
        if dialect == "SMBv1":
            dialect_display = f"{dialect}  [bold red](VULNERABLE - Deprecated)[/bold red]"
        else:
            dialect_display = f"[green]{dialect}[/green]"

        # Signing annotation
        if signing == "Required":
            signing_display = f"[green]{signing}[/green]  [green](Secure)[/green]"
        elif signing in ("Supported", "Disabled"):
            signing_display = f"[bold red]{signing}[/bold red]  [bold red](VULNERABLE to NTLM Relay)[/bold red]"
        else:
            signing_display = signing

        header_lines = [
            f"[bold]Target:[/bold]    {f['target']}:{f['port']}",
            f"[bold]Dialect:[/bold]   {dialect_display}",
            f"[bold]Signing:[/bold]   {signing_display}",
            f"[bold]Auth:[/bold]      {auth}",
            f"[bold]Time:[/bold]      {f['timestamp']}",
        ]
        c.print()
        c.print(Panel(
            "\n".join(header_lines),
            title="[bold]SMB Compliance Audit Report[/bold]",
            border_style=border_style,
            expand=False,
            padding=(1, 3),
        ))

        # ── Shares Table ──────────────────────────────────────────────────
        if f["shares"]:
            tbl = Table(
                title="SMB Share Permissions Audit",
                title_style="bold cyan",
                show_lines=False,
                padding=(0, 1),
            )
            tbl.add_column("Share Name", style="bold white", min_width=16)
            tbl.add_column("Remark / Type", min_width=18)
            tbl.add_column("Read Access", justify="center", min_width=8)
            tbl.add_column("Write Access", justify="center", min_width=8)

            for s in f["shares"]:
                r = "[green]Yes[/green]" if s["read"] else "[red]No[/red]"
                w = "[green]Yes[/green]" if s["write"] else "[red]No[/red]"
                remark_type = s["remark"] if s["remark"] else s["type"]
                tbl.add_row(s["name"], remark_type, r, w)

            c.print()
            c.print(tbl)

        # ── Password Policy Table ─────────────────────────────────────────
        if f["password_policy"]:
            pol = f["password_policy"]

            ptbl = Table(
                title="Domain / Local Password Policy",
                title_style="bold cyan",
                show_lines=False,
                padding=(0, 1),
            )
            ptbl.add_column("Policy", style="bold white", min_width=30)
            ptbl.add_column("Value", min_width=20)

            display_map = {
                "domain":                    "Domain",
                "min_password_length":       "Minimum Password Length",
                "password_history_length":   "Password History Length",
                "complexity_required":       "Complexity Required",
                "max_password_age":          "Maximum Password Age",
                "min_password_age":          "Minimum Password Age",
                "lockout_threshold":         "Account Lockout Threshold",
                "lockout_duration":          "Lockout Duration",
                "lockout_observation_window": "Lockout Observation Window",
            }

            for key, label in display_map.items():
                if key in pol:
                    val = pol[key]
                    # Highlight risky settings
                    val_str = str(val)
                    if key == "min_password_length" and isinstance(val, int) and val < 8:
                        val_str = f"[bold red]{val}[/bold red] ⚠ below 8"
                    elif key == "lockout_threshold" and isinstance(val, int) and val == 0:
                        val_str = "[bold red]0 (disabled)[/bold red] ⚠"
                    elif key == "complexity_required" and val is False:
                        val_str = "[bold red]False[/bold red] ⚠"
                    elif key == "complexity_required" and val is True:
                        val_str = "[green]True[/green]"
                    ptbl.add_row(label, val_str)

            c.print()
            c.print(ptbl)

        # ── Users ─────────────────────────────────────────────────────────
        if f["users"]:
            c.print()
            total = len(f["users"])
            active = sum(1 for u in f["users"] if u["status"] == "active")
            disabled = total - active

            if total <= USER_DISPLAY_THRESHOLD:
                utbl = Table(
                    title="Enumerated Users",
                    title_style="bold cyan",
                    show_lines=False,
                    padding=(0, 1),
                )
                utbl.add_column("RID", justify="right", style="dim", min_width=6)
                utbl.add_column("Username", style="bold white", min_width=24)
                utbl.add_column("Status", justify="center", min_width=10)

                for u in f["users"]:
                    status = (
                        "[green]active[/green]"
                        if u["status"] == "active"
                        else "[yellow]disabled[/yellow]"
                    )
                    utbl.add_row(str(u["rid"]), u["name"], status)

                c.print(utbl)
            else:
                c.print(Panel(
                    f"Successfully enumerated [bold]{total}[/bold] domain user(s)\n"
                    f"  [green]Active:[/green]   {active}\n"
                    f"  [yellow]Disabled:[/yellow] {disabled}\n\n"
                    f"[dim]Full list available in the JSON export (--json).[/dim]",
                    title="[bold cyan]Enumerated Users[/bold cyan]",
                    border_style="cyan",
                    expand=False,
                    padding=(1, 3),
                ))

        # ── Groups ────────────────────────────────────────────────────────
        if f["groups"]:
            c.print()
            gtbl = Table(
                title="Enumerated Groups / Aliases",
                title_style="bold cyan",
                show_lines=False,
                padding=(0, 1),
            )
            gtbl.add_column("RID", justify="right", style="dim", min_width=6)
            gtbl.add_column("Group Name", style="bold white", min_width=24)
            gtbl.add_column("Members", min_width=10)

            for g in f["groups"]:
                count = len(g["members"])
                if count == 0:
                    member_str = "[dim](none)[/dim]"
                elif count <= 5:
                    member_str = ", ".join(g["members"])
                else:
                    shown = ", ".join(g["members"][:5])
                    member_str = f"{shown} [dim](+{count - 5} more)[/dim]"
                gtbl.add_row(str(g["rid"]), g["name"], member_str)

            c.print(gtbl)

        # ── Active Sessions ───────────────────────────────────────────────
        if f["sessions"]:
            c.print()

            # Check if we got an access-denied sentinel
            has_error = any(s.get("error") for s in f["sessions"])
            real_sessions = [s for s in f["sessions"] if not s.get("error")]

            stbl = Table(
                title="Active SMB Sessions",
                title_style="bold cyan",
                show_lines=False,
                padding=(0, 1),
            )
            stbl.add_column("Username", style="bold white", min_width=20)
            stbl.add_column("Source Machine / IP", min_width=22)
            stbl.add_column("Active Time", justify="right", min_width=12)
            stbl.add_column("Idle Time", justify="right", min_width=10)

            if has_error and not real_sessions:
                err = next(s.get("error", "") for s in f["sessions"] if s.get("error"))
                if err == "ACCESS_DENIED":
                    stbl.add_row(
                        "[yellow]N/A[/yellow]",
                        "[yellow]N/A[/yellow]",
                        "[yellow]—[/yellow]",
                        "[dim]Administrative privileges required for this check[/dim]",
                    )
                else:
                    stbl.add_row(
                        "[red]Error[/red]",
                        f"[red]{err}[/red]",
                        "[red]—[/red]",
                        "[red]—[/red]",
                    )
            elif not real_sessions:
                stbl.add_row(
                    "[dim]—[/dim]",
                    "[dim]No active sessions found.[/dim]",
                    "[dim]—[/dim]",
                    "[dim]—[/dim]",
                )
            else:
                for s in real_sessions:
                    active_str = str(timedelta(seconds=s["active_time"]))
                    idle_str = str(timedelta(seconds=s["idle_time"]))
                    stbl.add_row(s["username"], s["source"], active_str, idle_str)

            c.print(stbl)

        # ── Spider / Exposed Files ────────────────────────────────────────
        if f["spider_results"]:
            c.print()

            if f.get("using_default_regex", False):
                c.print(
                    "[dim italic]Spidering using default high-value file "
                    "signatures (*.bak, *.sql, *.db, *.kdbx, *.config, "
                    "*.xml, *.env, *.ps1, *.pem, *.key, *.pfx, id_rsa, "
                    "web.config, unattend.xml)…[/dim italic]"
                )

            # Group matches by share for the tree view
            by_share: dict[str, list[dict]] = {}
            for m in f["spider_results"]:
                by_share.setdefault(m["share"], []).append(m)

            tree = Tree(
                "[bold red]⚠  Exposed / Backup Files[/bold red]",
                guide_style="red",
            )

            for share_name, matches in by_share.items():
                branch = tree.add(f"[bold yellow]\\\\{f['target']}\\{share_name}[/bold yellow]")
                for m in matches:
                    size_str = self._format_size(m["size"])
                    dl_note = "  [green]✓ downloaded[/green]" if m["downloaded"] else ""
                    branch.add(
                        f"[white]{m['path']}[/white]  "
                        f"[dim]({size_str})[/dim]{dl_note}"
                    )

            c.print(tree)

            downloaded_count = sum(1 for m in f["spider_results"] if m["downloaded"])
            summary = (
                f"\n  [bold]{len(f['spider_results'])}[/bold] sensitive file(s) discovered"
            )
            if downloaded_count:
                summary += f", [green]{downloaded_count}[/green] auto-downloaded"
            c.print(summary)

        # ── All Files (--list-files) ──────────────────────────────────────
        if f["all_files"]:
            c.print()

            by_share: dict[str, list[dict]] = {}
            for af in f["all_files"]:
                by_share.setdefault(af["share"], []).append(af)

            ftree = Tree(
                f"[bold cyan]All Files ({len(f['all_files'])} total)[/bold cyan]",
                guide_style="cyan",
            )

            for sname, files in sorted(by_share.items()):
                branch = ftree.add(
                    f"[bold yellow]\\\\{f['target']}\\{sname}[/bold yellow]  "
                    f"[dim]({len(files)} files)[/dim]"
                )
                for af in files:
                    sz = self._format_size(af["size"])
                    branch.add(f"[white]{af['path']}[/white]  [dim]({sz})[/dim]")

            c.print(ftree)

        # ── Vulnerability Heuristics ──────────────────────────────────────
        if f["vulnerabilities"]:
            c.print()

            vtbl = Table(
                title="Vulnerability Heuristics",
                title_style="bold cyan",
                show_lines=True,
                padding=(0, 1),
            )
            vtbl.add_column("Vulnerability", style="bold white", min_width=30)
            vtbl.add_column("Severity", justify="center", min_width=10)
            vtbl.add_column("Details", min_width=40)

            severity_styles = {
                "Critical": "bold red",
                "High": "red",
                "Medium": "yellow",
                "Info": "yellow",
            }

            for v in f["vulnerabilities"]:
                sev = v["severity"]
                style = severity_styles.get(sev, "white")
                vtbl.add_row(
                    f"[{style}]{v['vulnerability']}[/{style}]",
                    f"[{style}]{sev}[/{style}]",
                    v["details"],
                )

            c.print(vtbl)

        elif "vulnerabilities" in f:
            # Module was run but nothing triggered
            c.print()
            c.print(
                "[green]  ✓ No legacy SMB vulnerabilities detected.[/green]"
            )

        # ── Footer ────────────────────────────────────────────────────────
        c.print()
        c.rule(style="dim")

    def export_json(self, path: str) -> None:
        """Write all findings to a JSON file."""
        dest_dir = os.path.dirname(path)
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.findings, fh, indent=4, default=str)

        logging.info("Findings exported to %s", path)
        _console.print(f"  JSON report written to: [bold]{path}[/bold]")

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Return a human-friendly file-size string."""
        for unit in ("B", "KB", "MB", "GB"):
            if abs(size_bytes) < 1024:
                return f"{size_bytes:.1f} {unit}" if unit != "B" else f"{size_bytes} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _dialect_to_str(dialect_id: int) -> str:
        """Map an impacket dialect ID to a human-readable string."""
        mapping = {
            SMB_DIALECT: "SMBv1",
            SMB2_DIALECT_002: "SMBv2.0.2",
            SMB2_DIALECT_21: "SMBv2.1",
            SMB2_DIALECT_30: "SMBv3.0",
            SMB2_DIALECT_311: "SMBv3.1.1",
        }
        return mapping.get(dialect_id, f"Unknown(0x{dialect_id:04x})")

    @staticmethod
    def _detect_signing(conn: SMBConnection) -> str:
        """Determine SMB signing status: Required, Supported, or Disabled."""
        try:
            # SMBv2/v3 path — the underlying SMB3 object tracks SecurityMode
            smb_obj = conn.getSMBServer()

            # SMB2/3: SecurityMode flags from the negotiate response
            # Bit 0x01 = Signing Enabled, Bit 0x02 = Signing Required
            if hasattr(smb_obj, "_Session") and hasattr(smb_obj._Session, "get"):
                # SMB3 session dict style
                sec_mode = getattr(smb_obj, "_Connection", {}).get("RequireSigning", None)
                if sec_mode is True:
                    return "Required"

            # Try the public attribute used by impacket's SMB3 implementation
            if hasattr(smb_obj, "_SMBConnection__RequireSigning"):
                if smb_obj._SMBConnection__RequireSigning:
                    return "Required"

            # SMB2/3 negotiate SecurityMode field
            if hasattr(smb_obj, "_negResult"):
                neg = smb_obj._negResult
                if hasattr(neg, "fields"):
                    sec_mode = neg.fields.get("SecurityMode", 0)
                    if sec_mode & 0x02:
                        return "Required"
                    if sec_mode & 0x01:
                        return "Supported"

            # SMBv1 path — check the negotiate response flags
            if hasattr(smb_obj, "_dialects_data"):
                flags = getattr(smb_obj, "_dialects_data", None)
                if flags and hasattr(flags, "fields"):
                    sec_mode = flags.fields.get("SecurityMode", 0)
                    # SMBv1: bit 0x08 = signatures required
                    if sec_mode & 0x08:
                        return "Required"
                    if sec_mode & 0x04:
                        return "Supported"

            # Fallback: check the generic sign_required flag that some
            # impacket versions expose.
            if hasattr(smb_obj, "is_signing_required"):
                if callable(smb_obj.is_signing_required):
                    return "Required" if smb_obj.is_signing_required() else "Supported"

            # Last-resort heuristic: if the session is already signing,
            # treat it as required.
            if hasattr(smb_obj, "_SigningSessionKey") and smb_obj._SigningSessionKey:
                return "Required"

            if conn.isSigningRequired():
                return "Required"

        except Exception as exc:
            logging.debug("Signing detection heuristic error: %s", exc)

        # If we couldn't confirm signing, report conservatively
        return "Disabled"

    def disconnect(self) -> None:
        """Gracefully close the SMB connection if active."""
        if self.conn:
            try:
                self.conn.logoff()
                self.conn.close()
            except Exception:
                pass
            self.conn = None
            logging.info("Disconnected from %s.", self.target)

    # ── Remote File Viewer ────────────────────────────────────────────────

    def cat_file(self, share_path: str) -> None:
        """Read a remote file over SMB and print it with syntax highlighting."""
        c = _console

        # Parse SHARE/path
        parts = share_path.split("/", 1)
        if len(parts) < 2 or not parts[1]:
            c.print("[red]Invalid --cat format. Use: SHARE_NAME/path/to/file[/red]")
            return

        share_name = parts[0]
        remote_path = "/" + parts[1]
        wire_path = remote_path.replace("/", "\\")
        filename = parts[1].rsplit("/", 1)[-1]

        # Pre-flight size check — refuse files over 1 MB to avoid flooding the terminal
        cat_warn_size = 1 * 1024 * 1024
        try:
            entries = self.conn.listPath(share_name, wire_path)
            if entries:
                remote_size = entries[0].get_filesize()
                if remote_size > cat_warn_size:
                    c.print(
                        f"[bold red][!] File is {self._format_size(remote_size)} "
                        f"(larger than 1 MB).[/bold red]\n"
                        f"    Use [bold]--download[/bold] instead."
                    )
                    return
        except Exception:
            pass  # let the actual getFile call handle errors

        # Stream file into memory (hard cap at 10 MB as a safety net)
        max_cat_size = 10 * 1024 * 1024
        buf = bytearray()

        def _write(data: bytes) -> None:
            buf.extend(data)
            if len(buf) > max_cat_size:
                raise OverflowError("File exceeds 10 MB cat limit")

        try:
            self.conn.getFile(share_name, wire_path, _write)
        except SessionError as exc:
            error_code = exc.getErrorCode()
            if error_code == 0xC0000022:
                c.print(f"[red]Access denied:[/red] \\\\{share_name}{remote_path}")
            elif error_code == 0xC0000034:
                c.print(f"[red]File not found:[/red] \\\\{share_name}{remote_path}")
            else:
                c.print(f"[red]Error reading file:[/red] {exc}")
            return
        except OverflowError:
            c.print("[red]File exceeds 10 MB — use --download instead.[/red]")
            return
        except Exception as exc:
            c.print(f"[red]Error reading file:[/red] {exc}")
            return

        # Attempt UTF-8 decode, fall back to latin-1
        try:
            text = buf.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = buf.decode("utf-16")
            except UnicodeDecodeError:
                text = buf.decode("latin-1")

        # Determine a lexer hint from the extension for syntax highlighting
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        ext_to_lexer = {
            "py": "python", "ps1": "powershell", "sh": "bash",
            "xml": "xml", "json": "json", "yaml": "yaml", "yml": "yaml",
            "ini": "ini", "conf": "ini", "config": "xml",
            "sql": "sql", "html": "html", "css": "css", "js": "javascript",
            "env": "bash", "bat": "batch", "cmd": "batch",
            "pem": "text", "key": "text", "crt": "text",
        }
        lexer = ext_to_lexer.get(ext, "text")

        size_str = self._format_size(len(buf))
        c.print()
        c.print(Panel(
            Syntax(text, lexer, line_numbers=True, word_wrap=True),
            title=f"[bold]\\\\{share_name}{remote_path}[/bold]  [dim]({size_str})[/dim]",
            border_style="cyan",
            expand=True,
            padding=(0, 1),
        ))
        c.print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = build_argparser()
    args = parser.parse_args()

    # If no specific module selected and --all not set, default to --shares
    if not any([args.shares, args.policy, args.users, args.sessions, args.spider, args.vulns, args.all, args.cat]):
        args.shares = True

    # --all orchestrator: enable every module
    if args.all:
        args.shares = True
        args.policy = True
        args.users = True
        args.sessions = True
        args.spider = True
        args.vulns = True

    # Logging verbosity
    if args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose >= 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logging.basicConfig(format=LOG_FORMAT, level=log_level, stream=sys.stderr)

    auditor = SMBAuditor(args)

    try:
        auditor.connect()

        if not auditor.authenticate():
            sys.exit(1)

        # ── Cat (view remote file) ────────────────────────────────────────
        if args.cat:
            auditor.cat_file(args.cat)

        # ── Shares ────────────────────────────────────────────────────────
        if args.shares:
            logging.info("Starting share enumeration …")
            auditor.enum_shares()

        # ── Password policy ───────────────────────────────────────────────
        if args.policy:
            logging.info("Querying password policy …")
            auditor.get_password_policy()

        # ── Users / Groups ────────────────────────────────────────────────
        if args.users:
            logging.info("Enumerating users and groups …")
            auditor.enum_users()
            auditor.enum_groups()

        # ── Sessions ──────────────────────────────────────────────────────
        if args.sessions:
            logging.info("Enumerating active sessions …")
            auditor.enum_sessions()

        # ── Spider ────────────────────────────────────────────────────────
        if args.spider:
            logging.info("Spidering shares for backup files …")
            auditor.spider_shares()

        # ── Vulnerability heuristics ──────────────────────────────────────
        if args.vulns:
            logging.info("Running vulnerability heuristics …")
            auditor.check_vulnerabilities()

        # ── Output ────────────────────────────────────────────────────────
        auditor.print_findings()

        if args.json_file:
            auditor.export_json(args.json_file)

    except KeyboardInterrupt:
        logging.warning("Interrupted by user.")
    finally:
        auditor.disconnect()


if __name__ == "__main__":
    main()
