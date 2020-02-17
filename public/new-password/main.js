//main.js - fck-afd URL shortener - Maximilian Schiller
const input = document.getElementById('url-input'),
      input2 = document.getElementById('url-input2'),
      out = document.getElementById('out'),
      start = document.getElementById('start')


async function confirm(){
  const options = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({passwd: input.value, passwd2: input2.value})
  };
  const response = await fetch('/auth/new-password', options);
  const json = await response.json();
  if (json.status == 400){
    out.innerHTML = `<h1>Dein Token ist abgelaufen.</h1>`;
  }else if (json.status == 200){
    console.log(json);
    out.innerHTML = `<h1>Dein Passwort wurde erfolgreich geändert</h1>`;
    delete_cookie("token", "/", ".betahuhn.de")
    setTimeout(function(){ window.location.href = "https://auth.betahuhn.de"; }, 1000);
  }else if (json.status == 404){
    console.log(json);
    out.innerHTML = `<h1>Das Passwort darf keine Lücke enthalten</h1>`;
  }else if (json.status == 405){
    console.log(json);
    out.innerHTML = `<h1>Das Passwort ist zu lang (max. 20)</h1>`;
  }else if (json.status == 406){
    console.log(json);
    out.innerHTML = `<h1>Das Passwort ist zu kurz (min. 8)</h1>`;
  }else if (json.status == 401){
    console.log(json);
    out.innerHTML = `<h1>Die passwörter sind nicht identisch!</h1>`;
  }else if (json.status == 402){
    console.log(json);
    out.innerHTML = `<h1>Das neue Passwort darf nicht dem alten entsprechen!</h1>`;
  }
  else{
    out.innerHTML = `<h1>Es ist ein Fehler aufgetreten: ${json.status}</h1>`;
    
  }
}


function delete_cookie( name, path, domain ) {
  if( getCookie( name ) ) {
      document.cookie = name + "=" +
      ((path) ? ";path="+path:"")+
      ((domain)?";domain="+domain:"") +
      ";expires=Thu, 01 Jan 1970 00:00:01 GMT";
  }
}
function getCookie(name) {
  var nameEQ = name + "=";
  var ca = document.cookie.split(';');
  for(var i=0;i < ca.length;i++) {
      var c = ca[i];
      while (c.charAt(0)==' ') c = c.substring(1,c.length);
      if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
  }
  return null;
}














