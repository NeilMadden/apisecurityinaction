const apiUrl = 'https://localhost:4567';

function login(username, password) {
    let credentials = 'Basic ' + btoa(username + ':' + password);

    fetch(apiUrl + '/sessions', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': credentials
        }
    })
    .then(res => {
       if (res.ok) {
         res.json().then(json => {
            document.cookie = 'token=' + json.token +
                ';Secure;SameSite=strict';
            window.location.replace('/natter.html');
         });
       }
    })
    .catch(error => console.error('Error logging in: ', error));
}

window.addEventListener('load', function(e) {
    document.getElementById('login')
        .addEventListener('submit', processLoginSubmit);
});

function processLoginSubmit(e) {
    e.preventDefault();

    let username = document.getElementById('username').value;
    let password = document.getElementById('password').value;

    login(username, password);
    return false;
}
