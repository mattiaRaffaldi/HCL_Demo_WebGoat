function submit_secret_credentials() {
    var xhttp = new XMLHttpRequest();
    xhttp['open']('POST', 'InsecureLogin/login', true);
	var username = document.getElementsByName('username')[0].value;
	var password = document.getElementsByName('password')[0].value;
	xhttp['send'](JSON.stringify({username: username, password: password}))
}
