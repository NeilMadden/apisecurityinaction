function getCap(url, callback) {
    let capUrl = new URL(url);
    let token = capUrl.username;
    capUrl.username = '';
    capUrl.search = '?access_token=' + encodeURIComponent(token);

    return fetch(capUrl.href)
    .then(response => response.json())
    .then(callback)
    .catch(err => console.error('Error: ', err));
}
function loadMessages(link) {
    getCap(link.href, async messages => {
        for (let messageUrl of messages) {
            await loadMessage(messageUrl);
        }
    });
    return false;
}
function loadMessage(capUrl) {
    return getCap(capUrl, message => {
        let table = document.getElementById('messages');
        let row = table.appendChild(document.createElement('tr'));
        row.appendChild(document.createElement('td'))
           .textContent = message.author;
        row.appendChild(document.createElement('td'))
           .textContent = message.time;
        row.appendChild(document.createElement('td'))
           .textContent = message.message;
    });
}
