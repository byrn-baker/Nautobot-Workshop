"""Nautobot development configuration file."""

# pylint: disable=invalid-envvar-default
import os
import sys

from nautobot.core.settings import *  # noqa: F403  # pylint: disable=wildcard-import,unused-wildcard-import
from nautobot.core.settings_funcs import is_truthy, parse_redis_connection
from custom_jinja_filters import netaddr_filters  # noqa: F401

#
# Debug
#

DEBUG = is_truthy(os.getenv("NAUTOBOT_DEBUG", False))

TESTING = len(sys.argv) > 1 and sys.argv[1] == "test"

#
# Logging
#

LOG_LEVEL = "DEBUG" if DEBUG else "INFO"

#
# Redis
#

# Redis Cacheops
CACHEOPS_REDIS = parse_redis_connection(redis_database=1)

#
# Celery settings are not defined here because they can be overloaded with
# environment variables. By default they use `CACHES["default"]["LOCATION"]`.
#

# Enable installed plugins. Add the name of each plugin to the list.
# PLUGINS = ["nautobot_example_plugin"]
PLUGINS = [
    "nautobot_plugin_nornir", 
    "nautobot_bgp_models", 
    "nautobot_golden_config",
    ]

# Plugins configuration settings. These settings are used by various plugins that the user may have installed.
# Each key in the dictionary is the name of an installed plugin and its value is a dictionary of settings.
PLUGINS_CONFIG = {
    "nautobot_plugin_nornir": {
        "use_config_context": {"secrets": False, "connection_options": True},
        # Optionally set global connection options.
        "connection_options": {
            "napalm": {
                "extras": {
                    "optional_args": {"global_delay_factor": 1},
                },
            },
            "netmiko": {
                "extras": {
                    "global_delay_factor": 1,
                },
            },
        },
        "nornir_settings": {
            "credentials": "nautobot_plugin_nornir.plugins.credentials.env_vars.CredentialsEnvVars",
            "runner": {
                "plugin": "threaded",
                "options": {
                    "num_workers": 20,
                },
            },
        },
        "nautobot_golden_config": {
            "per_feature_bar_width": 0.15,
            "per_feature_width": 13,
            "per_feature_height": 4,
            "enable_backup": True,
            "enable_compliance": True,
            "enable_intended": True,
            "enable_sotagg": True,
            "enable_plan": True,
            "enable_deploy": True,
            "enable_postprocessing": False,
            "sot_agg_transposer": None,
            "postprocessing_callables": [],
            "postprocessing_subscribed": [],
            "jinja_env": {
                "undefined": "jinja2.StrictUndefined",
                "trim_blocks": True,
                "lstrip_blocks": False,
            },
            # "default_deploy_status": "Not Approved",
            # "get_custom_compliance": "my.custom_compliance.func"
        },
    },
    "nautobot_golden_config": {
        "per_feature_bar_width": 0.15,
        "per_feature_width": 13,
        "per_feature_height": 4,
        "enable_backup": True,
        "enable_compliance": True,
        "enable_intended": True,
        "enable_sotagg": True,
        "enable_plan": True,
        "enable_deploy": True,
        "enable_postprocessing": False,
        "sot_agg_transposer": None,
        "postprocessing_callables": [],
        "postprocessing_subscribed": [],
        "jinja_env": {
            "undefined": "jinja2.StrictUndefined",
            "trim_blocks": True,
            "lstrip_blocks": False,
        },
        # "default_deploy_status": "Not Approved",
        # "get_custom_compliance": "my.custom_compliance.func"
    },
}
