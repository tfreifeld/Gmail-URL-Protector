

chrome.runtime.sendMessage({message: "label"});

chrome.runtime.onMessage.addListener(
    function (request) {

        if(request.message === "vt-warn"){
            alert("VirusTotal API quota limit (4 per minute) reached!");
        }
        else if(request.message === "label-ready"){
            chrome.runtime.sendMessage({message: "show"});
        }
        else{
            console.warn("unrecognized message received " + request);
        }
    });