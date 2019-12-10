const header = document.getElementById('header'),
        start = document.getElementById('start'),
        name = document.getElementById('name'),
        button1 = document.getElementById('button1'),
        button2 = document.getElementById('button2'),
        button3 = document.getElementById('button3')

async function authenticate(){
    const options = {
        method: 'GET',
        headers: {
        'Content-Type': 'application/json'
        }
    };
    const response = await fetch('/api/home', options);
    const json = await response.json();
    console.log(json)
    if (json.status == 400){
        location.replace("/login?ref=auth.betahuhn.de/");
    }else if (json.status == 200){
        console.log(json.name);
        header.innerHTML = `<p>Hallo, ${json.name}</p>`;
        //name.innerHTML = `<p>${json.name}</p>`;
        button1.innerHTML = `<a href="/logout"><button class="btn btn--primary uppercase">Logout</button></a>`;
        //button2.innerHTML = `<a href="/new-password"><button class="btn btn--primary uppercase">Passwort Ändern</button></a>`;
        //button3.innerHTML = `<a class="bottom" href="https://map.betahuhn.de"><button class="btn btn--primary uppercase">View Map</button></a>`;
    }
    else{
        header.innerHTML = `<p id=text >${json.status}: Es ist ein Fehler aufgetreten, bitte veruche es erneut. </p>`;
    }
}

async function profile(){
    const options = {
        method: 'GET',
        headers: {
        'Content-Type': 'application/json'
        }
    };
    const response = await fetch('/api/home', options);
    const json = await response.json();
    console.log(json)
    if (json.status == 400){
        location.replace("/login?ref=auth.betahuhn.de/");
    }else if (json.status == 200){
        console.log(json.name);
        button1.innerHTML = `<p>Name: ${json.name}</p>`;
        button2.innerHTML = `<p>Email: ${json.email}</p>`;
        button3.innerHTML = `<p>User ID: ${json.user_id}</p>`;
        //button2.innerHTML = `<a href="/new-password"><button class="btn btn--primary uppercase">Passwort Ändern</button></a>`;
        //button3.innerHTML = `<a class="bottom" href="https://map.betahuhn.de"><button class="btn btn--primary uppercase">View Map</button></a>`;
    }
    else{
        header.innerHTML = `<p id=text >${json.status}: Es ist ein Fehler aufgetreten, bitte veruche es erneut. </p>`;
    }
}