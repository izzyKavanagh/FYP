import yaml

def load_config(path="firewall_config.yaml"):
    """
    Load firewall configuration from YAML file.
    """

    try:
        with open(path, "r") as file:
            config = yaml.safe_load(file)

        return config["firewall"]

    except Exception as e:
        print(f"[CONFIG ERROR] {e}")
        exit(1)