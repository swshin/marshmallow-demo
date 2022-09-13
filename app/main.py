import dataclasses
import os
import pdfkit       # It requires the wkhtmltopdf package.(sudo apt-get install wkhtmltopdf)
import time

from datetime import timedelta, datetime
from http import HTTPStatus
from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_marshmallow import Marshmallow
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt, get_jwt_identity
from flask_jwt_extended import jwt_required, JWTManager

from domain.record import RecordStatus, Record, load_record, write_record
from domain.member import Member, load_member, write_member


app = Flask(__name__)
ma = Marshmallow(app)

app.config['UPLOAD_FOLDER'] = "upload"

app.config["JWT_SECRET_KEY"] = "change_this"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

jwt = JWTManager(app)

member_demo: Member = load_member()
# record_demo = Record(rid=55555, status=RecordStatus.DONE.name, column_1="10y1m", column_2="10y6m", mid=1)
record_demo: Record = load_record()

class LoginSchema(ma.Schema):
    class Meta:
        fields = ["access_token", "refresh_token", "_links"]

    _links = ma.Hyperlinks(
        {
            "change_password": ma.URLFor("change_password", values=dict(mid="<mid>")),
            "analysis": ma.URLFor("analysis")
        }
    )


class ChangePasswordSchema(ma.Schema):
    class Meta:
        fields = ["_links"]

    _links = ma.Hyperlinks(
        {
            "self": ma.URLFor("change_password", values=dict(mid="<mid>")),
            "analysis": ma.URLFor("analysis")
        }
    )


class RefreshTokenSchema(ma.Schema):
    class Meta:
        fields = ["access_token", "_links"]

    _links = ma.Hyperlinks(
        {
            "analysis": ma.URLFor("analysis")
        }
    )


class RecordSchema(ma.Schema):

    class DataSchema(ma.Schema):
        class Meta:
            fields = [field.name for field in dataclasses.fields(Record)]
            fields.append("_links")

        _links = ma.Hyperlinks(
            {
                "get_record_report": ma.URLFor("get_record_report", values=dict(rid="<rid>"))
            }
        )

    class Meta:
        fields = ["record", "_links"]
   
    _links = ma.Hyperlinks(
        {
            "self": ma.URLFor("get_record", values=dict(rid="<record.rid>"))
        }
    )


class RecordStatusSchema(ma.Schema):
    class Meta:
        fields = ["rid", "status", "_links"]
    
    _links = ma.Hyperlinks(
        {
            "self": ma.URLFor("get_record_status", values=dict(rid="<rid>")),
            "get_record": ma.URLFor('get_record', values=dict(rid="<rid>"))
        }
    )


def validate_user(username, password):
    if username == member_demo.get_email() and password == member_demo.get_password():
        return member_demo

    return None


@jwt.token_verification_loader
def verify_token(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    type = jwt_payload["type"]

    if type == "refresh":
        stored_jti = member_demo.refresh_jti
    else:
        stored_jti = member_demo.access_jti

    return jti == stored_jti


@app.route("/api/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    member = validate_user(username, password)

    if not member:
        return jsonify(msg="Either the password is incorrect or the login ID does not exist."), HTTPStatus.UNAUTHORIZED

    # If first login token
    access_token = create_access_token(identity=member.mid, fresh=True)
    member_demo.access_jti = access_token

    refresh_token = create_refresh_token(identity=member.mid)
    member_demo.refresh_jti = refresh_token

    write_member(member_demo)

    login_schema = LoginSchema()
    return login_schema.dump(dict(mid=member.mid, access_token=access_token, refresh_token=refresh_token))


@app.route("/api/members/<mid>/password", methods=["PATCH"])
@jwt_required()
def change_password(mid):
    old_password = request.json.get("old_password")
    new_password = request.json.get("new_password")

    try:
        member_demo.change_password(old_password, new_password)
    except Exception as e:
        return jsonify(dict(msg=f'{e}')), HTTPStatus.FORBIDDEN

    change_password_schema = ChangePasswordSchema()
    return change_password_schema.dump(dict(mid=mid))


@app.route("/api/refresh-token", methods=["POST"])
@jwt_required(refresh=True)
def refresh_token():
    mid_jwt = get_jwt_identity()

    access_token = create_access_token(identity=mid_jwt, fresh=False)
    member_demo.access_jti = access_token

    write_member(member_demo)

    refresh_token_schema = RefreshTokenSchema()
    return refresh_token_schema.dump(dict(access_token=access_token))


@app.route("/api/records", methods=["POST"])
@jwt_required()
def analysis():

    mid_jwt = get_jwt_identity()

    file = request.files.get("file")
    if file:
        filename = file.filename
    else:
        filename = None

    form = request.form
    param_1 = form.get("param_1")
    param_2 = form.get("param_2")

    print(f"file={filename}, param_1={param_1}, param_2={param_2}")

    rid = int(time.time())
    record_demo.rid = str(rid)
    record_demo.status = RecordStatus.IN_PROGRESS.name
    record_demo.column_1 = param_1
    record_demo.column_2 = param_2
    record_demo.mid = mid_jwt

    write_record(record_demo)

    record_status_schema = RecordStatusSchema()
    return record_status_schema.dump(dict(rid=rid, status=RecordStatus.IN_PROGRESS.name))


@app.route("/api/records/<rid>", methods=["GET"])
@jwt_required()
def get_record(rid):
    mid_jwt = get_jwt_identity()

    print(f"mid_jwt={mid_jwt}, record_demo.member_id={record_demo}")

    if mid_jwt != str(record_demo.mid) or rid != str(record_demo.rid):
        return jsonify(dict(msg="No data found with the record ID")), HTTPStatus.NOT_FOUND

    exp_timestamp = get_jwt()["exp"]
    print(f"jwt={get_jwt()}, mid_jwt={mid_jwt}, exp_timestamp={datetime.fromtimestamp(exp_timestamp)}")

    record = Record(rid=rid, status=RecordStatus.DONE.name, column_1="value_1", column_2="value_2", mid=mid_jwt)
    record_response = {"record": RecordSchema.DataSchema().dump(record)}
    
    record_schema = RecordSchema()
    return record_schema.dump(record_response)


@app.route("/api/records/<rid>/status", methods=["GET"])
@jwt_required()
def get_record_status(rid):
    mid_jwt = get_jwt_identity()

    if mid_jwt != str(record_demo.mid) or rid != str(record_demo.rid):
        return jsonify(dict(msg="No data found with the record ID")), HTTPStatus.NOT_FOUND

    # data = {"rid": rid, "status": "COMPLETE"}
    data = {"rid": rid, "status": RecordStatus.IN_PROGRESS.name}
    # data = {"rid": rid, "status": "FAILED"}

    record_status_schema = RecordStatusSchema()
    return record_status_schema.dump(data)


@app.route("/api/records/<rid>/report", methods=["GET"])
@jwt_required()
def get_record_report(rid):
    mid_jwt = get_jwt_identity()

    if mid_jwt != str(record_demo.mid) or rid != str(record_demo.rid):
        return jsonify(dict(msg="No data found with the record ID")), HTTPStatus.NOT_FOUND
    
    # "A4" or "Letter"
    paper_size = request.args.get("paper_size")
    paper_size = str(paper_size).upper() if paper_size else 'A4'

    uploads_folder = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    filename = f'report_{rid}.pdf'

    filepath = os.path.join(uploads_folder, filename)

    # options = {
    #     'page-size': 'Letter',
    #     'margin-top': '0.75in',
    #     'margin-right': '0.75in',
    #     'margin-bottom': '0.75in',
    #     'margin-left': '0.75in',
    #     'encoding': "UTF-8",
    #     'custom-header': [
    #         ('Accept-Encoding', 'gzip')
    #     ],
    #     'cookie': [
    #         ('cookie-empty-value', '""')
    #         ('cookie-name1', 'cookie-value1'),
    #         ('cookie-name2', 'cookie-value2'),
    #     ],
    #     'no-outline': None
    # }

    options = {
        'page-size': paper_size,
        'margin-top': '0.75in',
        'margin-right': '0.75in',
        'margin-bottom': '0.75in',
        'margin-left': '0.75in',
        'encoding': "UTF-8",
        'custom-header': [
            ('Accept-Encoding', 'gzip')
        ],
        'cookie': [],
        'no-outline': None
    }

    pdfkit.from_string(render_template('report.html', paper_size=paper_size, rid=rid, mid=mid_jwt), filepath, options=options)

    try:
        return send_from_directory(uploads_folder, filename, as_attachment=True)
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050)
