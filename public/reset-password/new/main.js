//main.js - fck-afd URL shortener - Maximilian Schiller
const input = document.getElementById('url-input'),
      input2 = document.getElementById('url-input2'),
      out = document.getElementById('out'),
      start = document.getElementById('start')


async function confirm(){
  if(input.value != input2.value){
    out.innerHTML = `<h1>Passwords don't match</h1>`;
  }else{
    var url_string = window.location.href
    var url = new URL(url_string);
    var token = url.searchParams.get("token");
    console.log(token)
    const options = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({password: input.value, token: token})
    };
    const response = await fetch('/auth/new-password', options);
    const json = await response.json();
    if (json.status == 405){
      out.innerHTML = `<h1>Token expired. Request a new link <a href="/reset-password">here</a></h1>`;
    }else if (json.status == 200){
      console.log(json);
      out.innerHTML = `<h1>Password was successfully changed</h1>`;
      setTimeout(function(){ window.location.href = "https://auth.betahuhn.de"; }, 1000);
    }else if (json.status == 424){
      console.log(json);
      out.innerHTML = `<h1>Password can't contain spaces</h1>`;
    }else if (json.status == 425){
      console.log(json);
      out.innerHTML = `<h1>Password too long (max. 20)</h1>`;
    }else if (json.status == 426){
      console.log(json);
      out.innerHTML = `<h1>Password too short (min. 8)</h1>`;
    }else if (json.status == 401){
      console.log(json);
      out.innerHTML = `<h1>Passwords don't match</h1>`;
    }else if (json.status == 402){
      console.log(json);
      out.innerHTML = `<h1>New password can't be the same as old password</h1>`;
    }else{
      out.innerHTML = `<h1>An Error occurred: ${json.status}</h1>`;
      
    }
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














