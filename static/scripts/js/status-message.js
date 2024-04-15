window.onload = function() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");
    const statusMessage = document.getElementById("statusMessage");

    // This code checks the url "code" parameter to return specific status messages depending on the code
    if (code=="401") {
        statusMessage.textContent = "The username or password is incorrect";
        statusMessage.style.color = "red";
    } else if (code=="201") {
        statusMessage.textContent = "User created";
        statusMessage.style.color = "green";
    } else if (code=="409") {
        statusMessage.textContent = "User already exists";
        statusMessage.style.color = "red";
    } else if (code=="422") {
        statusMessage.textContent = "Password does not meet requirements";
        statusMessage.style.color = "red";
    } else if (code=="500") {
        statusMessage.textContent = "Internal server error";
        statusMessage.style.color = "red";
    } else if (code=="200") {
        statusMessage.textContent = "Saved";
        statusMessage.style.color = "green";
    } else if (code=="400") {
        statusMessage.textContent = "Passwords do not match";
        statusMessage.style.color = "red";
    }
};