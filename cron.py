import os
from datetime import datetime
from time import sleep

from main import main as job, logger as parent_logger

logger = parent_logger.getChild("cron")
interval = int(os.getenv("CRON_INTERVAL", "1"))


def main():
    while True:
        now = datetime.now()
        if now.second == 0 and now.minute % interval:
            try:
                job()
            except Exception as e:
                logger.exception({"error": f"{e.__class__.__name__}: {str(e)}"})
        sleep(1)


if __name__ == "__main__":
    main()
