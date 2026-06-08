from src.tools.custom.ffuf import FfufTool
from src.tools.custom.meg import MegTool
from src.tools.custom.secret_finder import SecretFinderTool
from src.tools.custom.nuclei import NucleiTool
from src.tools.custom.httpx import HttpxTool
from src.tools.custom.subfinder import SubfinderTool
from src.tools.custom.amass import AmassTool
from src.tools.custom.naabu import NaabuTool
# Phase 2 Tools
from src.tools.custom.gospider import GospiderTool
from src.tools.custom.katana import KatanaTool
from src.tools.custom.gau import GAUTool
from src.tools.custom.bbot import BBotTool
from src.tools.custom.shuffledns import ShuffleDNSTool
# Phase 3 Tools
from src.tools.custom.uro import UroTool
from src.tools.custom.forbidden_bypasser import ForbiddenBypasserTool
from src.tools.custom.param_fuzzer import ParamFuzzerTool
from src.tools.custom.s3scanner import S3ScannerTool
from src.tools.custom.subjack import SubjackTool
from src.tools.custom.notify import NotifyTool
from src.tools.custom.gowitness import GowitnessTool
from src.tools.custom.kiterunner import KiterunnerTool
from src.tools.custom.crawlee import CrawleeTool
# Phase 4 Tools - New Security Tools
from src.tools.custom.cloud_enum import CloudEnumTool
from src.tools.custom.subzy import SubzyTool
from src.tools.custom.scoutsuite import ScoutSuiteTool
from src.tools.custom.wafw00f import Wafw00fTool
from src.tools.custom.git_dumper import GitDumperTool
from src.tools.custom.tplmap import TplmapTool
from src.tools.custom.commix import CommixTool
from src.tools.custom.nosql_exploit import NoSQLExploitTool
from src.tools.custom.jwt_tool import JWTToolTool
from src.tools.custom.xxeinjector import XXEInjectorTool
from src.tools.custom.race_the_web import RaceTheWebTool
# Phase 5 Tools - New Security Features
from src.tools.custom.git_exposed_scanner import GitExposedScannerTool
from src.tools.custom.wayback_analyzer import WaybackAnalyzerTool
from src.tools.custom.dependency_confusion_scanner import DependencyConfusionScannerTool
from src.tools.custom.cloud_metadata_scanner import CloudMetadataScannerTool

__all__ = [
    # Phase 1
    "FfufTool", 
    "MegTool", 
    "SecretFinderTool",
    "NucleiTool",
    "HttpxTool",
    "SubfinderTool",
    "AmassTool",
    "NaabuTool",
    # Phase 2
    "GospiderTool",
    "KatanaTool",
    "GAUTool",
    "BBotTool",
    "ShuffleDNSTool",
    # Phase 3
    "UroTool",
    "ForbiddenBypasserTool",
    "ParamFuzzerTool",
    "S3ScannerTool",
    "SubjackTool",
    "NotifyTool",
    "GowitnessTool",
    "KiterunnerTool",
    "CrawleeTool",
    # Phase 4 - New Security Tools
    "CloudEnumTool",
    "SubzyTool",
    "ScoutSuiteTool",
    "Wafw00fTool",
    "GitDumperTool",
    "TplmapTool",
    "CommixTool",
    "NoSQLExploitTool",
    "JWTToolTool",
    "XXEInjectorTool",
    "RaceTheWebTool",
    # Phase 5 - Advanced Security Features
    "GitExposedScannerTool",
    "WaybackAnalyzerTool",
    "DependencyConfusionScannerTool",
    "CloudMetadataScannerTool",
]
