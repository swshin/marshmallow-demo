import json
import logging

from dataclasses import dataclass
from dataclasses_json import dataclass_json
from enum import Enum


RECORD_FILE = "record.json"


class RecordStatus(Enum):
    IN_PROGRESS = "IN_PROGRESS"
    DONE = "DONE"
    FAILED = "FAILED"


@dataclass_json
@dataclass
class Record:
    rid: str = None
    status: RecordStatus = None
    column_1: str = None
    column_2: str = None
    mid: str = None


def load_record() -> Record:
    with open(RECORD_FILE, "r") as f:
        try: 
            data = json.load(f)
            record = Record.from_dict(data)
            return record
        except json.JSONDecodeError as e:
            logging.error(f"error={e}")
        
    return Record()


def write_record(record: Record):
    with open(RECORD_FILE, "w") as f:
        json.dump(record.to_dict(), f, indent=4)
        