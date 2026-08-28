from enum import Enum


class ConnectionStatus(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATION_FAILED = "authentication_failed"
    CONNECTION_ERROR = "connection_error"
    HOST_KEY_ERROR = "host_key_error"
    PERMISSION_ERROR = "permission_error"
    FIREWALLD_NOT_INSTALLED = "firewalld_not_installed"
    FIREWALLD_NOT_RUNNING = "firewalld_not_running"


class ApplyTarget(str, Enum):
    RUNTIME = "runtime"
    PERMANENT = "permanent"
    BOTH = "both"


class TargetStatus(str, Enum):
    NOT_RUN = "not_run"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNVERIFIED = "unverified"
