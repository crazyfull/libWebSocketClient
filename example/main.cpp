#include <iostream>
#include <string>
#include <WebSocketClient/WebSocketClient.h>

// Callback when a message is received from the WebSocket server
void onMessageCallback(WebSocketClient* WebSocket, const WSMessage& message) {
    std::cout << "Received message: [" << message.Data << "] Type: " << message.MessageType << "\n";

    if (message.MessageType == WSMessageType::TEXT_UTF8) {
        // You can handle text messages here if needed
    }

    if (message.MessageType == WSMessageType::PING) {
        // Respond to ping with pong, echoing the data
        WebSocket->SendPong(message.Data);
        std::cout << "Sent Pong response: [" << message.Data << "]\n";
    }
}

// Callback when the WebSocket connection is established successfully
void onConnectCallback(WebSocketClient* WebSocket) {
    std::cout << "Connected to WebSocket server\n";
    WebSocket->SendMessage("I'm a WebSocket client");
}

// Callback when the WebSocket connection is closed
void onCloseCallback(WebSocketClient* WebSocket) {
    std::cout << "WebSocket connection closed\n";
}

// Callback when an error occurs on the WebSocket connection
void onErrorCallback(WebSocketClient* WebSocket, WSError& err) {
    std::cerr << "WebSocket error: " << err.Msg << "\n";
}

int main() {
    std::string url = "wss://ws.ifelse.io";

    // Create WebSocket client instance
    WebSocketClient WebSocket;

    // Set up callbacks for WebSocket events
    WebSocket.onMessage(onMessageCallback);
    WebSocket.onConnect(onConnectCallback);
    WebSocket.onClose(onCloseCallback);
    WebSocket.onError(onErrorCallback);

    // Enable masking for client messages (usually recommended for clients)
    WebSocket.setUsingMask(true);

    // Enable SSL certificate validation (recommended for secure connections)
    WebSocket.setDisableCertificateValidation(false);

    // Connect to the WebSocket server
    WebSocket.Connect(url);

    // Wait for user input before sending messages (to keep the program running)
    std::cout << "Press Enter to send a text message...\n";
    std::cin.get();
    WebSocket.SendMessage("Hi from WebSocketClient");

    std::cout << "Press Enter to send a Ping frame...\n";
    std::cin.get();
    WebSocket.SendPing("Ping data");

    std::cout << "Press Enter to send a Pong frame...\n";
    std::cin.get();
    WebSocket.SendPong("Pong data");

    std::cout << "Press Enter to exit...\n";
    std::cin.get();

    // WebSocket destructor will close the connection gracefully
    return 0;
}
