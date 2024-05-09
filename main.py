from web.templates import create_app
from os import environ as env

app = create_app()
if __name__ == "__main__":
    app.run(debug=True,host="0.0.0.0", port=env.get("PORT", 5000))


