let messages = [];
let name = null;

function setName() {
	name = document.getElementById("name").value;
	let nameContainer = document.getElementById("name-container");
	nameContainer.style.display = "none";
}

function addMessage() {
	let message = document.getElementById("message").value;
	messages.push({name: name, message: message});
	
	let messageList = document.getElementById("messages");
	messageList.innerHTML = "";
	
	for (let i = 0; i < messages.length; i++) {
		let messageItem = document.createElement("p");
		messageItem.innerText = messages[i].name + ": " + messages[i].message;
		messageList.appendChild(messageItem);
	}
	
	document.getElementById("message").value = "";
	
	let xhttp = new XMLHttpRequest();
	xhttp.onreadystatechange = function() {
		if (this.readyState == 4 && this.status == 200) {
			console.log("Mensaje guardado en el servidor");
		}
	};
	xhttp.open("POST", "save-message.php", true);
	xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
	xhttp.send("name=" + name + "&message=" + message);
}