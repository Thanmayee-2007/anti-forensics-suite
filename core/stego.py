import cv2
import numpy as np
import math

class StegoAnalyzer:
    @staticmethod
    def _chi2_cdf(x: float, df: int) -> float:
        """
        Pure Python Chi-Square Cumulative Distribution Function (CDF).
        Calculates lower incomplete gamma via log-series expansion to eliminate SciPy DLL dependencies.
        """
        if x <= 0 or df <= 0:
            return 0.0
            
        a = df / 2.0
        g = x / 2.0
        
        sum_val = 1.0 / a
        term = 1.0 / a
        for i in range(1, 200):
            term *= g / (a + i)
            sum_val += term
            if term < 1e-12 * sum_val:
                break
                
        try:
            log_p = a * math.log(g) - g - math.lgamma(a) + math.log(sum_val)
            return min(1.0, max(0.0, math.exp(log_p)))
        except (ValueError, OverflowError):
            return 0.0

    @staticmethod
    def lsb_visual_attack(image_np: np.ndarray, channel: int = 0) -> np.ndarray:
        """
        Extracts the Least Significant Bit (LSB) from a specified RGB channel 
        and scales bit 0 to maximum intensity (255) to visually reveal hidden patterns.
        """
        if len(image_np.shape) == 3:
            channel_data = image_np[:, :, channel]
        else:
            channel_data = image_np
            
        # Isolate bit 0 (P & 1) and scale to 255
        lsb_plane = (channel_data & 1) * 255
        return lsb_plane.astype(np.uint8)

    @classmethod
    def chi_square_analysis(cls, image_np: np.ndarray) -> tuple[float, float, str]:
        """
        Performs Chi-Square statistical analysis on adjacent Pairs of Values (PoVs).
        Detects frequency flattening caused by LSB substitution.
        """
        if len(image_np.shape) == 3:
            gray = cv2.cvtColor(image_np, cv2.COLOR_RGB2GRAY)
        else:
            gray = image_np
            
        flat = gray.flatten()
        counts = np.bincount(flat, minlength=256)
        
        chi2_stat = 0.0
        degrees_of_freedom = 0
        
        for k in range(128):
            y_2k = counts[2 * k]
            y_2k1 = counts[2 * k + 1]
            
            # Expected average frequency after random payload embedding
            y_expected = (y_2k + y_2k1) / 2.0
            
            if y_expected > 0:
                chi2_stat += ((y_2k - y_expected) ** 2) / y_expected
                chi2_stat += ((y_2k1 - y_expected) ** 2) / y_expected
                degrees_of_freedom += 1

        dof = max(1, degrees_of_freedom - 1)
        p_value = cls._chi2_cdf(chi2_stat, dof)
        
        if p_value > 0.95:
            verdict = "HIGH CONFIDENCE: LSB Steganography Detected"
        elif p_value > 0.70:
            verdict = "SUSPICIOUS: Potential Embedded Data"
        else:
            verdict = "CLEAN: Natural Pixel Distribution"
            
        return chi2_stat, p_value, verdict

    @staticmethod
    def generate_variance_heatmap(image_np: np.ndarray) -> np.ndarray:
        """
        Calculates local pixel variance using a Laplacian kernel to generate an entropy heatmap.
        """
        if len(image_np.shape) == 3:
            gray = cv2.cvtColor(image_np, cv2.COLOR_RGB2GRAY)
        else:
            gray = image_np
            
        blurred = cv2.GaussianBlur(gray, (3, 3), 0)
        laplacian = cv2.Laplacian(blurred, cv2.CV_64F)
        abs_laplacian = np.uint8(np.absolute(laplacian))
        heatmap = cv2.applyColorMap(abs_laplacian, cv2.COLORMAP_JET)
        return cv2.cvtColor(heatmap, cv2.COLOR_BGR2RGB)