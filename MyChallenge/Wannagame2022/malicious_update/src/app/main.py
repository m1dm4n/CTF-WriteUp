import os
from flask import Flask, request, send_from_directory
from werkzeug.utils import secure_filename
import tempfile
import secure_installer # install your update

app = Flask(__name__, static_url_path='/static')
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.zip']


@app.route('/')
def index():
    return send_from_directory(os.getcwd(), 'index.html'), 200


@app.route('/update', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        filename = secure_filename(f.filename)
        if filename == '':
            return 'WTF hacker lord?????', 400
        file_ext = os.path.splitext(filename)[1]
        if file_ext != '.zip':
            return "I don't like that thing just send me Zip files plz!", 400
        with tempfile.NamedTemporaryFile(prefix="application_update_", suffix='.zip') as temp:
            temp.write(f.stream.read())
            temp.flush()
            try:
                secure_installer.verify_and_install(temp.name)
            except Exception as exp:
                return "There was error while using your update :(. Error: " + exp.__str__(), 400
        return "Your update was installed successfully.", 200
    elif request.method == 'GET':
        return 'Waiting for your update :(', 200
    else:
        return "Don't understand what's you are doing!", 400


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
