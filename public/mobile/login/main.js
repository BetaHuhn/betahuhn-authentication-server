const email = document.getElementById('email-input'),
    passwd = document.getElementById('passwd-input'),
    error = document.getElementById('error')

    async function shorten(email, passwd){
        var url_string = window.location.href
        var url = new URL(url_string);
        var ref = url.searchParams.get("ref");
        const data = {email, passwd};
        const options = {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(data)
        };
        const response = await fetch('/api/login', options);
        const json = await response.json();
        if (json.status == 400){
            error.innerHTML = `<p id=text >Wrong password</p>`;
        }else if (json.status == 401){
            error.innerHTML = `<p id=text >User does not exist</p>`;
        }else if (json.status == 200){
            console.log("login success");
            if(ref == null){
                window.location.replace("/");
            }else{
                console.log("Redirecting to " + ref)
                window.location.replace("https://" + ref);
            }
        }else{
            error.innerHTML = `<p id=text >${json.status}: Es ist ein Fehler aufgetreten, bitte veruche es erneut. </p>`;
        }
    }

function button() {
    shorten(email.value, passwd.value)
}

passwd.addEventListener("keyup", function(event) {
    if (event.keyCode === 13) {
      event.preventDefault();
      document.getElementById("upload-button").click();
    }
}); 