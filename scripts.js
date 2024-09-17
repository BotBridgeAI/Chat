document.addEventListener('DOMContentLoaded', () => {
        const ESettingslastNUMsentencesSlider = document.getElementById('ESettingslastNUMsentencesSlider');
        const ESettingslastNUMsentencesValue = document.getElementById('ESettingslastNUMsentencesValue');

        ESettingslastNUMsentencesSlider.addEventListener('input', () => {
            ESettingslastNUMsentencesValue.textContent = "Last " + ESettingslastNUMsentencesSlider.value + " Sentences";
            // Here you can add code to handle the setting change
            // For example, updating a global setting or sending it to a server
        });
    });
    document.addEventListener('DOMContentLoaded', () => {
        const ESettingsRandomNUMsentencesSlider = document.getElementById('ESettingsRandomNUMsentencesSlider');
        const ESettingsRandomNUMsentencesValue = document.getElementById('ESettingsRandomNUMsentencesValue');

        ESettingsRandomNUMsentencesSlider.addEventListener('input', () => {
            ESettingsRandomNUMsentencesValue.textContent = "Select " + ESettingsRandomNUMsentencesSlider.value + " Random Sentences";
            // Here you can add code to handle the setting change
            // For example, updating a global setting or sending it to a server
        });
    });

    document.addEventListener('DOMContentLoaded', () => {
        const SettingsMaxTokensSlider = document.getElementById('SettingsMaxTokensSlider');
        const SettingsMaxTokensValue = document.getElementById('SettingsMaxTokensValue');

        SettingsMaxTokensSlider.addEventListener('input', () => {
            SettingsMaxTokensValue.textContent = SettingsMaxTokensSlider.value + " Tokens";
            // Here you can add code to handle the setting change
            // For example, updating a global setting or sending it to a server
        });
    });

    function toggleExpertSettings() {
        const checkbox = document.getElementById('show-expert');
        const expertSettings = document.getElementById('expert-settings');

        // If the checkbox is checked, display the expert settings
        if (checkbox.checked) {
            expertSettings.style.display = 'block';
        } else {
            expertSettings.style.display = 'none';
        }
    }
    async function checkAPIStatusDropdown(apiUrl) {
        try {
            const response = await fetch(apiUrl + '/v1/internal/model/info');
            console.log(apiUrl);
            if (response.ok) {
                return 'Up and Running';
            } else {
                return 'Error (' + response.status + ')';
            }
        } catch (error) {
            return 'Down';
        }
    }

    document.addEventListener('DOMContentLoaded', async () => {
        try {
            const response = await fetch('/api/send');
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            const data = await response.json();

            const dropdown = document.getElementById('model');
            dropdown.innerHTML = '';

            const options = await Promise.all(data.map(async (api) => {
                const status = await checkAPIStatusDropdown(api.api_url);
                const option = document.createElement('option');
                option.value = api.api_url;
                option.textContent = `${api.api_name} - Status: ${status}`;
                return option;
            }));

            options.forEach(option => dropdown.appendChild(option));

        } catch (error) {
            console.error('Error fetching API links:', error);
        }
    });

    let settings = {
        persona: '',
        context: '',
        greeting: '',
        temperature: 0.5,
        model: 'https://hose-apparatus-wilderness-computer.trycloudflare.com',
        //         charName: ''
    };

    function updateCharacterList() {
        const characterList = document.getElementById('character-list');
        characterList.innerHTML = '';

        const keys = Object.keys(localStorage);
        keys.forEach(key => {
            if (key.startsWith('chatbotCharacter_')) {
                const charName = key.replace('chatbotCharacter_', '');
                const listItem = document.createElement('li');
                listItem.textContent = charName;

                // Remove button
                const removeBtn = document.createElement('button');
                removeBtn.textContent = '×'; // Use a "×" character
                removeBtn.className = 'remove-btn';
                removeBtn.onclick = (event) => {
                    event.stopPropagation();
                    if (confirm(`Are you sure you want to delete the character "${charName}"?`)) {
                        localStorage.removeItem(key);
                        updateCharacterList();
                    }
                };

                listItem.appendChild(removeBtn);
                listItem.className = 'character-item';
                listItem.onclick = () => loadCharacter(charName, listItem);
                characterList.appendChild(listItem);
            }
        });
    }

    function addNewCharacter() {
        const charName = prompt('Enter a name for the new character:');
        if (charName) {
            settings.charName = charName;
            saveCharacter();
            updateSettings();
            updateCharacterList();
        }
    }

    setInterval(checkAPIStatus, 60000); // Check API status every 60 seconds

    async function checkAPIStatus() {
        document.getElementById('api-status-text').textContent = 'Checking';
        document.getElementById('api-status-text').className = 'status-checking';

        try {
            const response = await fetch(document.getElementById('model').value + '/v1/internal/model/info');
            if (response.ok) {
                document.getElementById('api-status-text').textContent = 'Up and Running';
                document.getElementById('api-status-text').className = 'status-up';
            } else {
                document.getElementById('api-status-text').textContent = 'Error (' + response.status +")";
                document.getElementById('api-status-text').className = 'status-code';
            }
        } catch (error) {
            document.getElementById('api-status-text').textContent = 'Down';
            document.getElementById('api-status-text').className = ' status-down';
        }
    }


    function saveCharacter() {
        settings.persona = document.getElementById('persona').value;
        settings.context = document.getElementById('context').value;
        settings.greeting = document.getElementById('greeting').value;
        settings.temperature = parseFloat(document.getElementById('temperature').value);
        settings.model = document.getElementById('model').value;
        if (settings.charName) {
            localStorage.setItem('chatbotCharacter_' + settings.charName, JSON.stringify(settings));
            alert('Character saved!');
            updateCharacterList();
        } else {
            alert('Please enter a character name.');
        }
    }

    function loadCharacter(charName, listItem) {
        clearCurrentBotMessage();

        const characterData = localStorage.getItem('chatbotCharacter_' + charName);
        if (characterData) {
            settings = JSON.parse(characterData);
            document.getElementById('persona').value = settings.persona;
            document.getElementById('context').value = settings.context;
            document.getElementById('greeting').value = settings.greeting;
            document.getElementById('temperature').value = settings.temperature;
            document.getElementById('model').value = settings.model;
            highlightCharacter(listItem);
            sendGreeting(); // Send greeting message on character load
        } else {
            alert('Character not found.');
        }
    }

    function highlightCharacter(selectedItem) {
        const listItems = document.querySelectorAll('#character-list li');
        listItems.forEach(item => item.classList.remove('selected'));
        selectedItem.classList.add('selected');
    }

    function uploadCharacter() {
        const fileInput = document.getElementById('upload-json');
        const file = fileInput.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(event) {
                try {
                    const jsonData = JSON.parse(event.target.result);

                    // Check for the expected fields in the JSON
                    if (jsonData.char_persona && jsonData.char_greeting && jsonData.world_scenario) {
                        // Update the HTML elements with the JSON data
                        document.getElementById('persona').value = jsonData.char_persona;
                        document.getElementById('context').value = jsonData.world_scenario;
                        document.getElementById('greeting').value = jsonData.char_greeting;
                        document.getElementById('temperature').value = jsonData.temperature || 0.5; // Default value if temperature is not provided

                        alert('Character uploaded and settings updated successfully!');
                    } else {
                        alert('Invalid JSON format. Ensure it contains the necessary fields.');
                    }
                } catch (e) {
                    alert('Failed to parse JSON.');
                }
            };
            reader.readAsText(file);
            addNewCharacter();
        } else {
            alert('Please select a file to upload.');
        }
    }

    function downloadJSONConfig() {
        const persona = document.getElementById('persona').value;
        const context = document.getElementById('context').value;
        const greeting = document.getElementById('greeting').value;
        const temperature = parseFloat(document.getElementById('temperature').value) || 0.5;

        // Construct JSON object
        const jsonData = {
            char_persona: persona,
            char_greeting: greeting,
            world_scenario: context,
            temperature: temperature
        };

        // Convert JSON object to string
        const jsonString = JSON.stringify(jsonData, null, 4);

        // Create a blob with the JSON string
        const blob = new Blob([jsonString], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'character-config.json';

        // Trigger the download
        a.click();

        // Clean up
        URL.revokeObjectURL(url);
    }

    // Helper function to extract values based on a keyword
    function extractValue(jsonString, keyword) {
        const regex = new RegExp(`${keyword}:\\s*"([^"]+)"`, 'i');
        const match = jsonString.match(regex);
        return match ? match[1] : '';
    }

    function updateSettings() {
        checkAPIStatus();
        //processMessageDataImportance();
        if (messagessent.value > 8) {
            settings.persona = document.getElementById('persona').value;
            settings.context = document.getElementById('context').value;
            settings.greeting = '';
            settings.temperature = parseFloat(document.getElementById('temperature').value);
            settings.model = document.getElementById('model').value;
        } else {
            settings.persona = document.getElementById('persona').value;
            settings.context = document.getElementById('context').value;
            settings.greeting = document.getElementById('greeting').value;
            settings.temperature = parseFloat(document.getElementById('temperature').value);
            settings.model = document.getElementById('model').value;

            //Controlled Message Data Importance
            messagedataimportance.lusermsg = lastUserMessage;

            //document.getElementById('advanced-debugging').value = messagedataimportance.lusermsg;
        }
    }

    let lastBotMessage = ''; // Variable to store the last bot message
    let lastUserMessage = ''; // Variable to store the last user message

    // Function to clear the content of the current bot message element
    function clearCurrentBotMessage() {
        if (currentBotMessageElement) {
            currentBotMessageElement.innerHTML = ''; // Clear the existing content
            lastBotMessage = ''; // Clear the last bot message content
        }
    }

    let messagedataimportance = {
        lusermsg: '',
        messagehistory: '',
        messagehistorytrimmed: '',
    };

    function getAllMessagesExceptLast() {
        const chatContainer = document.getElementById('chat-container');

        // Select all message elements
        const messageElements = chatContainer.querySelectorAll('.message');

        // If there are less than two messages, return an empty string
        if (messageElements.length < 2) {
            return '';
        }

        // Get all messages except the last one
        const messagesExceptLast = Array.from(messageElements)
        .slice(0, -1) // Exclude the last message
        .map(message => message.textContent.trim()) // Get text content of each message
        .join(' '); // Join all messages into a single string

        return messagesExceptLast;
    }

    function processMessageDataImportance() {
        const chatContainer = document.getElementById('chat-container');
        // messagedataimportance.messagehistory = chatContainer.textContent;
        messagedataimportance.messagehistory = getAllMessagesExceptLast();
        console.log(messagedataimportance.messagehistory);
        let fullText = messagedataimportance.messagehistory;

        // Step 1: Split the message history into sentences
        //let sentences = fullText.split(/(?<=\.)\s+/); // Splits by sentence, assuming period ends a sentence
        let sentences = fullText.split(/(?<=[.!?])\s+(?!\.\.\.)/); //"This is a sentence! And this is another? But this one... keeps going."

        // Step 2: Get the last # sentences
        let numLastSentences = parseInt(ESettingslastNUMsentencesSlider.value, ESettingslastNUMsentencesSlider.value);
        let lastSentences = sentences.slice(-numLastSentences).join(' '); // Take the last X sentences

        // Step 3: Get the sentences before the last X sentences
        let remainingSentences = sentences.slice(0, sentences.length - numLastSentences)
        .filter(sentence => !sentence.includes('◀') && !sentence.includes('▶')); // Exclude sentences with ◀ or ▶

        // Filter out any sentences containing the last bot message
        if (lastBotMsg) {
            remainingSentences = remainingSentences.filter(sentences => !sentences.includes(lastBotMsg));
            console.log("Removed: " + sentences + " || " + lastBotMsg)
        }

        // Step 4: Generate weights for sentences, inversely proportional to their index
        let weightedSentences = remainingSentences.map((sentence, index) => ({
            sentence: sentence,
            weight: remainingSentences.length - index
        }));
        let totalWeight = weightedSentences.reduce((a, b) => a + b.weight, 0);

        // Function to select a weighted random item
        function getRandomWeightedIndex() {
            let random = Math.random() * totalWeight;
            for (let i = 0; i < weightedSentences.length; i++) {
                if (random < weightedSentences[i].weight) {
                    return i;
                }
                random -= weightedSentences[i].weight;
            }
            return weightedSentences.length - 1; // Fallback to the last item
        }

        // Debugging: Log weights and sentences
        console.log('Weighted Sentences:', weightedSentences);

        // Step 5: Randomly select X sentences from the weighted list
        let numRandomSentences = parseInt(ESettingsRandomNUMsentencesSlider.value, ESettingsRandomNUMsentencesSlider.value);
        let selectedSentences = [];
        for (let i = 0; i < Math.min(numRandomSentences, weightedSentences.length); i++) {
            const index = getRandomWeightedIndex();
            selectedSentences.push(weightedSentences[index]);
            console.log(`Selected Sentence: "${weightedSentences[index].sentence}" with weight ${weightedSentences[index].weight}`);

            // Remove selected sentence and corresponding weight from the list to avoid repetition
            weightedSentences.splice(index, 1);
            totalWeight = weightedSentences.reduce((a, b) => a + b.weight, 0); // Recalculate total weight
        }

        // Sort selected sentences by their weights
        selectedSentences.sort((b, a) => b.weight - a.weight);

        // Step 6: Combine the last X sentences and the randomly selected sentences
        let finalText = selectedSentences.map(item => item.sentence).join(' ') + "\n\n" + lastSentences;

        // Step 7: Display or use the result
        messagedataimportance.messagehistorytrimmed = finalText;
        //document.getElementById('advanced-debugging').value = messagedataimportance.messagehistorytrimmed;
    }

    async function sendMessage() {
        document.getElementById('advanced-debugging').value = currentBotMessageElement.innerHTML;
        const userInput = document.getElementById('user-input');
        const message = userInput.value.trim();
        if (!message) return;

        if (!isResend) {
            processMessageDataImportance();
            // Update lastBotMessage to the current content
            lastBotMsg = currentBotMessageElement.textContent || currentBotMessageElement.innerHTML;
            console.log('Updated lastBotMsg:', lastBotMsg);
            lastUserMessage = message; // Store the last user message
            messagessent = messagessent + 1;
            document.getElementById('messages-sent').value = messagessent;
            displayMessage(message, 'user');
            userInput.value = '';
            botMessages = []; // Reset bot messages on new send
            currentBotMessageElement = null;
        }

        lastBotMsg = lastBotMsg ? lastBotMsg : settings.greeting; // Fallback to empty string if null

        if (document.getElementById('model').value == '') {
            document.getElementById('model').value = 'https://hose-apparatus-wilderness-computer.trycloudflare.com';
        }
        try {
            updateSettings();
            const requestData = {
                messages: [
                    // { role: 'user', content: messagedataimportance.lusermsg },
                    //{ role: 'system', content: settings.greeting },
                    { role: 'assistant', content: settings.persona },
                    { role: 'system', content: settings.context },
                    { role: 'system', content: messagedataimportance.messagehistorytrimmed },
                    { role: 'assistant', content: lastBotMsg },
                    { role: 'user', content: message }
                ],
                max_tokens: SettingsMaxTokensSlider.value,
                stream: true,
                temperature: settings.temperature
            };

            // Log the request body to the console for debugging
            console.log('Request Data:', JSON.stringify(requestData, null, 2));

            const response = await fetch("/api/send", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(requestData)
            });


            if (response.body) {
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let result = '';

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    const chunk = decoder.decode(value, { stream: true });
                    const matches = chunk.match(/"content":\s*"([^"]*)"/);
                    if (matches && matches[1]) {
                        const content = matches[1];
                        result += content;
                        // ORIGINAL DISPLAY MESSAGE FUNCTION >> displayMessage(content, 'bot', false); // Pass 'false' to indicate the message is being generated
                        clearCurrentBotMessage(); //ATTEMPT TO fully format actively while message is being generated.
                        displayMessage(result, 'bot', false); // Pass 'false' to indicate the message is being generated

                    }
                }

                if (result) {
                    clearCurrentBotMessage();
                    displayMessage(result, 'bot', true); // Pass 'true' to indicate the message is finalized
                }
            } else {
                const data = await response.json();
                const botMessage = data.choices[0].message.content;
                displayMessage(botMessage, 'bot', false);
            }

        } catch (error) {
            console.error('Error:', error);
            displayMessage('Sorry, there was an error processing your request.', 'bot', false);
        } finally {
            isResend = false;
        }
    }

    function regenerateMessage() {
        if (lastUserMessage) {
            settings.context = settings.context.replace(lastBotMessage, '').trim();
            //messagedataimportance.historytrimmed = messagedataimportance.messagehistorytrimmed.replace(lastBotMessage, '').trim();
            //processMessageDataImportance();
            clearCurrentBotMessage();
            isResend = true;
            document.getElementById('user-input').value = lastUserMessage;
            sendMessage();
        } else {
            displayMessage('No previous user message found to regenerate.', 'bot');
        }
    }

    function usernameupdated () {

        if ( messagessent == 0) {
            currentBotMessageElement.innerHTML = '';
            const greeting = settings.greeting;
            displayMessage(greeting, 'bot');
        }
    }


    function sendGreeting() {
        messagessent = 0;
        const greeting = settings.greeting;
        if (greeting) {
            displayMessage(greeting, 'bot');
        }
    }

    let userName = '{{user}}';
    let currentBotMessageElement = null;
    let botMessages = []; // Array to store bot messages
    let currentBotMessageIndex = -1; // Index to track current bot message
    let lastBotMsg = null;

    function displayMessage(content, sender, isFinal = false) {

        userName = document.getElementById('user-name').value.trim();
        if (!userName) { userName = "{{user}}" }

        const chatContainer = document.getElementById('chat-container');
        const sanitizedContent = content
        .replace(/([.!?])(?!\.\.\.)(\s*)/g, "$1 ") // Ensure single space after . ? !
        .replace(/\\n/g, '<br>') // Convert literal \n to <br>
        .replace(/\\(?!n)/g, '') // Remove backslashes not followed by n
        .replace(/\n/g, '<br>') // Convert newline characters to <br> (if needed)
        .replace(/\*(.*?)\*/g, '<i>$1</i>') // Convert *text* to <i>text</i>
        //.replace(/(\r\n|\n|\r)/g, '<br>') // Convert all types of newlines to <br>
        //.replace(/\\n/g, '<br>') // Replace literal \n with <br>
        //.replace(/\\(?!n)/g, '') // Remove any backslashes not followed by 'n'
        //.replace(/\\/, '') // Remove backslashes
        //.replace(/\*(.*?)\*/g, '<i>$1</i>'); // Replace *text* with <i>text</i>
        .replace(/{{user}}/g, userName) // Replace {{user}} with the actual user name
        //.replace(/{{char}}/g, charName); // Replace {{char}} with the file char name


        if (sender === 'bot') {
            // Remove previous bot message header if exists
            const previousHeader = document.querySelector('.message-header');
            if (previousHeader) {
                previousHeader.remove();
            }

            // Create a new message header with navigation arrows
            const messageHeader = document.createElement('div');
            messageHeader.className = 'message-header';
            messageHeader.innerHTML = `
            <span class="nav-arrows ${currentBotMessageIndex === 0 ? 'disabled' : ''}" onclick="navigateBotMessages(-1)">&#9664;</span>
            <span class="nav-arrows ${currentBotMessageIndex === botMessages.length - 1 ? 'disabled' : ''}" onclick="navigateBotMessages(1)">&#9654;</span>
            `;

            // Create or update the current bot message element
            if (!currentBotMessageElement) {
                currentBotMessageElement = document.createElement('div');
                currentBotMessageElement.className = `message ${sender}`;
                chatContainer.appendChild(currentBotMessageElement);
            }

            // Append message header and content
            chatContainer.insertBefore(messageHeader, currentBotMessageElement);
            currentBotMessageElement.innerHTML += sanitizedContent;

            if (isFinal) {
                botMessages.push(currentBotMessageElement.innerHTML);
                currentBotMessageIndex = botMessages.length - 1;
            }

            // Update arrow states
            updateArrowStates();
        } else {
            const messageElement = document.createElement('div');
            messageElement.className = `message ${sender}`;
            messageElement.innerHTML = sanitizedContent;
            chatContainer.appendChild(messageElement);
        }

        // chatContainer.scrollTop = chatContainer.scrollHeight; //Scrolls to bottom as new message is generated.
        //document.getElementById('advanced-debugging').value = chatContainer.textContent;

        //messagedataimportance.messagehistory = chatContainer.textContent;
        const lastBotMessageElement = chatContainer.querySelector('.message.bot:last-child'); // Select the last bot message element
    }
    let isResend = false;

    function regenerateMessage() {
        // Remove the last bot message from the context
        if (lastUserMessage) {
            settings.context = settings.context.replace(lastBotMessage, '').trim(); // Use last bot message

            clearCurrentBotMessage(); // Clear the last bot message
            isResend = true; // Set flag to indicate resend
            document.getElementById('user-input').value = lastUserMessage;

            sendMessage(); // Resend the last user message
        } else {
            displayMessage('No previous user message found to regenerate.', 'bot');
        }
    }

    function navigateBotMessages(direction) {
        if (currentBotMessageIndex === -1) return; // No messages to navigate

        const newIndex = currentBotMessageIndex + direction;
        if (newIndex >= 0 && newIndex < botMessages.length) {
            currentBotMessageIndex = newIndex;
            const content = botMessages[currentBotMessageIndex];
            currentBotMessageElement.innerHTML = content;


            // Update lastBotMessage to the current content
            lastBotMsg = currentBotMessageElement.textContent || currentBotMessageElement.innerHTML;
            console.log('Updated lastBotMsg (navigated):', lastBotMsg);

            // Update arrow states
            updateArrowStates();
        }
    }


    async function updateQueueCounter() {
        // Fetch the number of jobs in the queue
        const queueCount = document.querySelector('#queue-count');
        const queueResponse = await fetch('/api/queue-status');
        const queueData = await queueResponse.json();
        const queueLength = queueData.queueLength;
        queueCount.textContent = queueLength;

        // Apply color class based on queue length
        if (queueLength >= 3 && queueLength <= 10) {
            queueCount.className = 'queue medium';
        } else if (queueLength > 10) {
            queueCount.className = 'queue high';
        } else {
            queueCount.className = 'queue low';
        }
    }

    // Fetch queue status every 5 seconds
    setInterval(updateQueueCounter, 5000);



    function updateArrowStates() {
        const leftArrow = document.querySelector('.nav-arrows:first-of-type');
        const rightArrow = document.querySelector('.nav-arrows:last-of-type');

        if (leftArrow) {
            leftArrow.classList.toggle('disabled', currentBotMessageIndex === 0);
        }
        if (rightArrow) {
            rightArrow.classList.toggle('disabled', currentBotMessageIndex === botMessages.length - 1);
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        updateCharacterList();
        checkAPIStatus();
    });
