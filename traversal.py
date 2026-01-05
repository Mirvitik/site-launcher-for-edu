from flask import Flask, request, send_from_directory, render_template

app = Flask(__name__)


@app.route('/')
def index():
    images = ['cat.jpg', 'cat2.jpg', 'cat3.jpg']
    return render_template('traversal.html', title='Сайт для скачивания файлов', images=images)


@app.route('/download')
def download_file():
    filename = request.args.get('file')

    return send_from_directory('static', filename, as_attachment=True)


if __name__ == "__main__":
    app.run()
