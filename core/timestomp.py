import os
import datetime

class TimestompDetector:
    @staticmethod
    def analyze_timestamps(filepath: str) -> dict:
        """
        Inspects file system timestamps for nanosecond truncation and logical sequence anomalies.
        """
        stat = os.stat(filepath)
        
        ctime = datetime.datetime.fromtimestamp(stat.st_ctime)
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
        atime = datetime.datetime.fromtimestamp(stat.st_atime)
        
        anomalies = []
        
        # Check logical sequence: Modification timestamp predating Creation timestamp
        if mtime < ctime:
            anomalies.append(
                "CRITICAL: Modification timestamp predates Creation timestamp ($STD_INFO tampering)."
            )
            
        # Check sub-second precision truncation (common artifact of automated SetFileTime scripts)
        if mtime.microsecond == 0 and ctime.microsecond == 0:
            anomalies.append(
                "SUSPICIOUS: Zero nanosecond precision across timestamps (userland API modification)."
            )
            
        return {
            "created": ctime.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "modified": mtime.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "accessed": atime.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "anomalies": anomalies,
            "status": "TIMESTOMPED" if anomalies else "INTACT"
        }