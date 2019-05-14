const apiUrl = 'https://localhost:4567';

function createSpace(name, owner) {
    let csrfToken = localStorage.csrf;
    if (!csrfToken) {
        window.location.replace('/login.html');
        return;
    }
    let data = {name: name, owner: owner};

    fetch(apiUrl + '/spaces', {
        method: 'POST',
        credentials: 'include',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        }
    })
    .then(response => {
        if (response.ok) {
            return response.json();
        } else if (response.status === 401) {
            window.location.replace('/login.html');
        } else {
            throw Error(response.statusText);
        }
    })
    .then(json => console.log('Created space: ', json.name, json.uri))
    .catch(error => console.error('Error: ', error));}

window.addEventListener('load', function(e) {
    document.getElementById('createSpace')
        .addEventListener('submit', processFormSubmit);
});

function processFormSubmit(e) {
    e.preventDefault();

    let spaceName = document.getElementById('spaceName').value;
    let owner = document.getElementById('owner').value;

    createSpace(spaceName, owner);

    return false;
}
