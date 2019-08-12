'use strict';

let currentHistoryId;
let accessGranted = false;

let tabId;
let extensionLabelId;

const gmailApiKey = "hidden";
const vtApiKey = "hidden";

/**
 * Load stored params upon background script's load
 */
onload = function () {

    console.log("onload called");

    chrome.storage.local.get(['currentHistoryId', 'extensionLabelId'], function (result) {
        currentHistoryId = result.currentHistoryId;
        extensionLabelId = result.extensionLabelId;
    });
};

/**
 * Listen for messages from content script
 */
chrome.runtime.onMessage.addListener(
    function (request, sender) {

        if (request.message === "label") {
            tabId = sender.tab.id;
            getAuth(getLabels);
        } else if (request.message === "show") {

            chrome.pageAction.show(tabId);

            if (currentHistoryId === undefined) {
                getAuth(getProfile);
            }

        } else {
            console.log(`Unrecognized message received from content script:
            ${request.message}`);
        }
    });
/**
 * Listen for clicks on the page action button
 */
chrome.pageAction.onClicked.addListener(tab => {

        chrome.pageAction.hide(tab.id, () => {

            getAuth(getNewMessagesIds);
        });

    }
);


/**
 * Create the extension unique label
 * @param token
 */
function createLabel(token) {

    validateToken(token);
    if (!accessGranted) {
        return;
    }

    const url = "https://www.googleapis.com/gmail/v1/users/me/labels";

    const requestBody = {
        labelListVisibility: "labelShow",
        messageListVisibility: "show",
        name: "Gmail URL Protector"
    };

    const createLabelResponse = gmailFetch(token, "POST", false, url, {
        key: gmailApiKey
    }, requestBody);

    createLabelResponse.then(response => {
        if (!response.ok) {
            handleAuthorizationExpiration(response, token);
        }
    });


    createLabelResponse.then(response => response.json()).then(result => {

        extensionLabelId = result.id;
        console.log("Created label:");
        console.log({result});
        chrome.tabs.sendMessage(tabId, {message: "label-ready"});


    });
}

/**
 * Get labels in the authenticated user's mailbox
 * @param token
 */
function getLabels(token) {

    validateToken(token);
    if (!accessGranted) {
        return;
    }

    const url = "https://www.googleapis.com/gmail/v1/users/me/labels";

    const labelsResponse = gmailFetch(token, "GET", false, url, {
        key: gmailApiKey
    });

    labelsResponse.then(response => {
        if (!response.ok) {
            handleAuthorizationExpiration(response, token);
        }
    });


    labelsResponse.then(response => response.json()).then(result => {

        let found = false;
        for (let i = 0; i < result.labels.length; i++) {
            if (result.labels[i].name === "Gmail URL Protector") {
                extensionLabelId = result.labels[i].id;
                found = true;
                break;
            }
        }

        if (found) {

            chrome.tabs.sendMessage(tabId, {message: "label-ready"});

        } else {
            createLabel(token);
        }
    });

}

/**
 * Get the authenticated user profile (needed to ger current history id)
 * @param token
 */
function getProfile(token) {

    validateToken(token);
    if (!accessGranted) {
        return;
    }

    const url = "https://www.googleapis.com/gmail/v1/users/me/profile";

    const profileResponse = gmailFetch(token, "GET", false, url, {
        key: gmailApiKey
    });

    profileResponse.then(response => {
        if (!response.ok) {
            handleAuthorizationExpiration(response, token);
        }
    });


    profileResponse.then(response => response.json()).then(result => {
        currentHistoryId = result.historyId;
        console.log("currentHistoryId was set as " + currentHistoryId);
        getNewMessagesIds(token);
    });
}

/**
 * Send url for scanning using VirusTotal's api
 * @param targetUrl url to scan
 * @returns {Promise<Response>} Scan results
 */
function requestUrlScan(targetUrl) {
    console.log(`Sending url ${targetUrl} for scan request`);

    const url = `https://www.virustotal.com/vtapi/v2/url/scan?apikey=${vtApiKey}&url=${targetUrl}`;

    const init = {
        method: 'POST',
        async: false,
        headers: {

            'Content-Type': "application/x-www-form-urlencoded"
        }
    };

    return fetch(url, init).then(response => {

        if (response.status === 204) {
            console.warn("API quota limit reached");
            chrome.tabs.sendMessage(tabId, {message: "vt-warn"});

        } else {
            return response.json();
        }
    }).then(response => {
        if (response.response_code === 1) {
            return {result: response.scan_id, success: true};
        } else {
            console.warn(`scan request of url ${targetUrl} returned the following message: ${response.verbose_msg}`);
            return undefined;
        }
    });
}

/**
 * Ask for a report for a given url or a previous scan using VirusTotal's api
 * @param resource url or scan_id to ask report for
 * @returns {Promise<Response>} Report results
 */
function requestUrlReport(resource) {

    console.log(`Sending resource ${resource} for report request`);

    const url = `https://www.virustotal.com/vtapi/v2/url/report?apikey=${vtApiKey}&resource=${resource}`;

    const init = {
        method: 'GET',
        async: false,
        headers: {

            'Content-Type': "application/x-www-form-urlencoded"
        }
    };

    return fetch(url, init).then(response => {

        if (response.status === 204) {
            console.warn("API quota limit reached");
            chrome.tabs.sendMessage(tabId, {message: "vt-warn"});
        } else {
            return response.json();
        }
    }).then(response => {
        if (response.response_code === 1) {
            return {result: response.positives, success: true};
        } else if (response.response_code === 0) {
            return {result: undefined, success: false};
        } else {
            console.warn(`report request of resource ${resource} returned the following message: ${response.verbose_msg}`);
            return undefined;
        }
    });
}

/**
 * Lookup a url found in message
 * @param targetUrl url to check
 * @returns result
 */
function lookupUrl(targetUrl) {

    return new Promise(function (resolve) {
        requestUrlReport(targetUrl.decoded.toLowerCase()).then(result => {
            if (result.success) {

                resolve({url: targetUrl.original, result: result.result > 0});
            } else {
                requestUrlScan(targetUrl.decoded.toLowerCase()).then(result => {
                    if (result !== undefined) {
                        requestUrlReport(result.result).then(result => {
                            if (result !== undefined) {
                                if (result.result !== undefined) {
                                    resolve({url: targetUrl.original, result: result.result > 0});
                                    return;
                                }
                            }
                            console.warn("Url lookup failed");
                            resolve({url: targetUrl.original, result: -1});
                        })
                    }
                });
            }
        });
    });
}


/**
 * Ask the user for access
 * @param callback to perform upon access approval
 */
function getAuth(callback) {
    chrome.identity.getAuthToken({interactive: true}, callback);
}

/**
 * Validate our token
 * @param token
 */
function validateToken(token) {
    if (token === undefined) {
        console.warn(chrome.runtime.lastError.message);
        accessGranted = false;
        alert("You must allow Gmail URL Protector access in order to use it." +
            "Click on the Gmail URL Protector icon (near the address bar) when you are ready");
    } else {
        accessGranted = true;
    }
}

/**
 * In case our authorization has expired, remove token and go
 * ask for a new one
 * @param response
 * @param token
 */
function handleAuthorizationExpiration(response, token) {
    if (response.status === 401) {
        console.log("Authorization expired. Remove token and request authorization again");
        chrome.identity.removeCachedAuthToken({token: token}, getAuth);
    }
}

/**
 * Log that a message with a given id was not found
 * @param response http request response
 * @param id of the message
 */
function handleMessageNotFound(response, id) {

    if (response.status === 404) {
        response.json().then(response => {
            if (response.error.message === "Not Found")
                console.log(`Message by id ${id} was not found`);
            else
                console.log(`Unexpected error when looking for message by id ${id}` + response.error.message);
        })
    }
}

/**
 * Get the messages according to the ids we received
 * @param ids of the messages to get
 * @param token
 */
function getMessagesByIds(ids, token) {

    function getMessage(id) {

        console.log("getting message with id " + id);

        validateToken(token);
        if (!accessGranted)
            return;

        const url = "https://www.googleapis.com/gmail/v1/users/me/messages/" + id;

        const getMsgResponse = gmailFetch(token, "GET", true, url, {format: "raw", key: gmailApiKey}, {});

        getMsgResponse.then(response => {
            if (!response.ok) {
                handleAuthorizationExpiration(response, token);
                handleMessageNotFound(response, id);
            }
        });

        return getMsgResponse.then(response => response.json());

    }

    /**
     * A barrier to make sure that the page action button will
     * become available again and reload the page only after all
     * checkups have been carried out to completion
     * @type {{pop, close, push}}
     */
    const barrier = Barrier({
        sync: () => {
            chrome.pageAction.show(tabId);
            chrome.tabs.reload(tabId);

        }
    });
    ids.forEach(id => barrier.push(id));
    barrier.close();

    const messagesPromises = ids.map(getMessage);
    messagesPromises.forEach(promise => promise.then(message => {

        let found = false;
        for (let i = 0; i < message.labelIds.length; i++) {
            if (message.labelIds[i] === extensionLabelId) {
                found = true;
                break;
            }
        }
        if (found) {
            barrier.pop(message.id);
        } else {
            lookupMessage(message, token, barrier);
        }

    }));


}

/**
 * Modify the message with the lookup results
 * @param message to modify
 * @param results
 * @param decoding of the message
 * @returns the modified message
 */
function modifyMessage(message, results, decoding) {

    for (let i = 0; i < results.length; i++) {
        const url = results[i].url;
        const regex = new RegExp("\(\?\<\=" + url + "[\"|']\.\*>" + "\)\.\*\(\?\=</a>\)", "gs");

        const result = results[i].result;
        const matches = decoding.match(regex);

        if (result) {

            for (const match of matches) {
                decoding = decoding.replace(regex, " [Blocked by Gmail URL Protector]");

                const hrefRegex = new RegExp("\(\?\<\=href=\(3D\)\?\[\"\|'\]\)" + url + "\(\?\=\[\"\|'\]\)", "gs");
                decoding = decoding.replace(hrefRegex, "BLOCKED!");
            }

        } else if (result === -1) {
            for (const match of matches) {
                decoding = decoding.replace(regex, " [Gmail URL Protector could not analyze: " + match + "]");
            }
        } else {
            for (const match of matches) {
                decoding = decoding.replace(regex, "[Verified: " + match + "]");
            }
        }
        //TODO: need to fix the case where same address appear several times in mail.
    }

    message.labelIds.push(extensionLabelId);
    message.raw = base64url_encode(decoding);
    return message;

}

/**
 * Decode a mail message from url-safe base64 encoding
 * @param message to decode
 */
function decodeMessage(message) {
    const raw = message.raw;
    return base64_decode(raw);
}

/**
 * Move original message to the mailbox's trash, since we will
 * insert our modified message
 * @param message to trash
 * @param token
 */
function trashOriginalMessage(message, token) {

    validateToken(token);
    if (!accessGranted) {
        return;
    }

    const url = "https://www.googleapis.com/gmail/v1/users/me/messages/" + message.id + "/trash";

    const trashResponse = gmailFetch(token, "POST", true, url, {
        key: gmailApiKey
    });

    trashResponse.then(response => {
        if (!response.ok) {
            handleAuthorizationExpiration(response, token);
        }
    });


    trashResponse.then(response => response.json());

}

/**
 * Lookup message for urls
 * @param message to lookup
 * @param token
 * @param barrier
 */
function lookupMessage(message, token, barrier) {

    const decoding = decodeMessage(message);
    const matches = decoding.match(/(?<=href=(3D)?["|']).*?(?=["|'])/gs);

    if (matches !== null) {

        const urls = matches.map(url => {

            return {
                decoded: quotedPrintable.decode(url), original: url
            }
        });

        const promises = [];

        urls.forEach(url => {
                const resultPromise = lookupUrl(url);
                promises.push(resultPromise);
            }
        );

        Promise.all(promises).then(results => {
            trashOriginalMessage(message, token);
            insertModifiedMessage(modifyMessage(message, results, decoding), token, barrier);
        })
    } else {
        console.log("No urls found in message id " + message.id);
        barrier.pop(message.id);

    }
}

/**
 * Insert our modified version of the message, updated
 * with its lookup results
 * @param message to insert
 * @param token
 * @param barrier
 */
function insertModifiedMessage(message, token, barrier) {

    validateToken(token);
    if (!accessGranted) {
        return;
    }

    const url = "https://www.googleapis.com/gmail/v1/users/me/messages";

    const insertResponse = gmailFetch(token, "POST", true, url, {
        key: gmailApiKey
    }, message);

    insertResponse.then(response => {
        if (!response.ok) {
            handleAuthorizationExpiration(response, token);
        }
    });


    insertResponse.then(response => response.json()).then(() => {

        barrier.pop(message.id);
    });


}

/**
 * Get ids of messages which have been added to the inbox
 * since our currentHistoryId
 * @param token
 */
function getNewMessagesIds(token) {

    validateToken(token);
    if (!accessGranted) {
        return;
    }

    const url = "https://www.googleapis.com/gmail/v1/users/me/history";

    const historyListResponse = gmailFetch(token, "GET", false, url, {
        key: gmailApiKey, "startHistoryId": currentHistoryId,
        "historyTypes": "messageAdded", "labelId": "INBOX"
    }, {});

    historyListResponse.then(response => {
        if (!response.ok) {
            handleAuthorizationExpiration(response, token);
        }
    });

    historyListResponse.then(response => response.json()).then(result => {

        currentHistoryId = result.historyId;
        console.log("currentHistoryId was set as " + currentHistoryId);
        const histories = result.history;

        const newMsgsIds = (histories === undefined) ? [] :
            histories.map(history => history.messagesAdded)
                .map(messages => messages.map(message => message.message.id))
                .reduce((acc, curr) => acc.concat(curr), []);

        if (newMsgsIds.length === 0) {
            console.log("No new messages detected");
            chrome.pageAction.show(tabId);

        } else {
            getMessagesByIds(newMsgsIds, token);
        }
    });
}

/**
 * Make an http request (using fetch) to the gmail API.
 * @param token
 * @param method GET/POST
 * @param async whether the request should be asynchronous
 * @param url of the request
 * @param queryParams
 * @param body request body
 * @param contentType
 * @returns {Promise<Response>}
 */
function gmailFetch(token = -1, method = "", async = true, url = "", queryParams = {}, body = {}, contentType = "application/json") {


    if (token === -1) {
        console.log("Invalid token");
    }

    const init = {
        method: method,
        async: async,
        headers: {
            Authorization: 'Bearer ' + token,
            'Content-Type': contentType,
        },
        body: (method === "GET") ? undefined : JSON.stringify(body),
        'contentType': 'json'

    };

    if (!jQuery.isEmptyObject(queryParams)) {
        const paramStr = Object.entries(queryParams).map(([k, v]) => `${k}=${v}`).join("&");
        url = url + "?" + paramStr;

    }

    return fetch(url, init);
}

/**
 * Upon suspension of the background script, store the currentHistoryId and extensionLabelId
 */
chrome.runtime.onSuspend.addListener(function () {
    console.log("Unloading.");
    chrome.storage.local.set({currentHistoryId: currentHistoryId});
    chrome.storage.local.set({extensionLabelId: extensionLabelId});
});


