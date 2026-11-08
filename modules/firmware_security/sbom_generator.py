from typing import List, Dict, Any

class FirmwareSBOMGenerator:
    """Inventories embedded open-source libraries and Linux kernel packages found in firmware."""

    @staticmethod
    def generate_firmware_sbom(components: List[Dict[str, str]]) -> Dict[str, Any]:
        return {
            "target_type": "FIRMWARE_IMAGE",
            "component_count": len(components),
            "components": components,
            "format": "SENTRIX-Firmware-SBOM/v4"
        }
