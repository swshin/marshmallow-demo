from dataclasses import dataclass
from dataclasses_json import dataclass_json
from distutils.file_util import write_file
import json
import logging

from flask_jwt_extended import decode_token


MEMBER_FILE = "member.json"


@dataclass_json
@dataclass
class Member:
    mid: str = None
    email: str = None
    password: str = None
    access_jti: str = None
    refresh_jti: str = None

    def change_password(self, old_password, new_password):
        if old_password == self.get_password():
            self.password = new_password
            write_member(self)
        else:
            raise Exception("The old password is incorrect")


def load_member():
    with open(MEMBER_FILE, "r") as f:
        try: 
            data = json.load(f)
            member = Member.from_dict(data)
            return member
        except json.JSONDecodeError as e:
            logging.error(f"error={e}")
        
    return Member()


def write_member(member: Member):
    with open(MEMBER_FILE, "w") as f:
        json.dump(member.to_dict(), f, indent=4)
