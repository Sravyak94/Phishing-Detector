chrome.runtime.sendMessage(document.URL, (response) => {
    // 3. Got an asynchronous response with the data from the background
    console.log('received user data', response);
    if (response == 1) {
        alert('It is a Legitimate Website!');
    } else {
        alert('Beware!!! It is a Phishing Website!');
    }
    //initializeUI(response);
});