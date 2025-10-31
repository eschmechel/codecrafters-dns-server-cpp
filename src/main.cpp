#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <sstream>

std::vector<uint8_t> createDNSMessage ( uint16_t packetID, 
                                        int QRID,int OPCODE,int AA, int TC, int RD,
                                        int RA, int Z, int AD, int CD, int RCODE,
                                        uint16_t numOfQuestions,
                                        uint16_t numOfAnswers,
                                        uint16_t numOfAuthorityRRs,
                                        uint16_t numOfAdditionalRRs
                                    );

std::vector<std::string> split (const std::string &s, char delim);


int main() {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // Disable output buffering
    setbuf(stdout, NULL);

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std::cout << "Logs from your program will appear here!" << std::endl;

    int udpSocket;
    struct sockaddr_in clientAddress;

    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) {
        std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
        return 1;
    }

    // Since the tester restarts your program quite often, setting REUSE_PORT
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }

    sockaddr_in serv_addr = { 
                            .sin_family = AF_INET,
                            .sin_port = htons(2053),
                            .sin_addr = { htonl(INADDR_ANY) },
                            };

    if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) != 0) {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }

    int bytesRead;
    char buffer[512];
    socklen_t clientAddrLen = sizeof(clientAddress);

    while (true) {
        // Receive data
        bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddrLen);
        if (bytesRead == -1) {
            perror("Error receiving data");
            break;
        }

        buffer[bytesRead] = '\0';
        std::cout << "Received " << bytesRead << " bytes: " << buffer << std::endl;

        // Create an empty response
        char response[1] = { '\0' };
        std::vector<uint8_t> dnsMessage = createDNSHeader(1234,0,0,0,0,0,0,0,0,0,0,1,0,0,0);

        // Send response

        if (sendto(udpSocket, dnsMessage.data(), dnsMessage.size(), 0, reinterpret_cast<struct sockaddr*>(&clientAddress), sizeof(clientAddress)) == -1) {
            perror("Failed to send response");
        }
    }

    close(udpSocket);

    return 0;
}

//Create DNS Header
std::vector<uint8_t> createDNSHeader ( uint16_t packetID, 
                                        int QRID,int OPCODE,int AA, int TC, int RD,
                                        int RA, int Z, int AD, int CD, int RCODE,
                                        uint16_t numOfQuestions,
                                        uint16_t numOfAnswers,
                                        uint16_t numOfAuthorityRRs,
                                        uint16_t numOfAdditionalRRs
                                    ){
    uint8_t byte1 = static_cast<uint8_t>((packetID & 0xFF00) >> 8);
    uint8_t byte2 = static_cast<uint8_t>((packetID & 0x00FF));
    uint8_t byte3 = 0;
    //bit 7
    byte3 |= (QRID << 7);

    //bit 6..3 OPCODE
    constexpr uint8_t MASK = 0b0111'1000;
    byte3 = (byte3 & ~MASK) | ((OPCODE & 0x0F) << 3);
    byte3 |= (AA << 2);
    byte3 |= (TC << 1);
    byte3 |= (RD << 0);

    uint8_t byte4 = 0;
    byte4 |= (RA << 7);
    byte4 |= (Z << 6);
    byte4 |= (AD << 5);
    byte4 |= (CD << 4);
    byte4  = ((byte4 & 0xF0) | (RCODE & 0x0F)); 

    uint8_t byte5 = static_cast<uint8_t>((numOfQuestions & 0xFF00) >> 8);
    uint8_t byte6 = static_cast<uint8_t>((numOfQuestions & 0x00FF));

    uint8_t byte7 = static_cast<uint8_t>((numOfAnswers & 0xFF00) >> 8);
    uint8_t byte8 = static_cast<uint8_t>((numOfAnswers & 0x00FF));

    uint8_t byte9 = static_cast<uint8_t>((numOfAuthorityRRs & 0xFF00) >> 8);
    uint8_t byte10 = static_cast<uint8_t>((numOfAuthorityRRs & 0x00FF));

    uint8_t byte11 = static_cast<uint8_t>((numOfAdditionalRRs & 0xFF00) >> 8);
    uint8_t byte12 = static_cast<uint8_t>((numOfAdditionalRRs & 0x00FF));

    return std::vector<uint8_t>{byte1,byte2,byte3,byte4,byte5,byte6,byte7,byte8,byte9,byte10,byte11,byte12};

}

std::vector<uint8_t> createDNSQuestion(std::string domainName, uint16_t type, uint16_t className){
    std::vector<std::string> domainSplit = split(domainName, '.');

    std::vector<uint8_t>domainBytes = {};
    for (size_t i = 0; i < domainSplit.size(); i++){
        uint8_t domainPartLen = domainSplit[i].size();
        domainBytes.push_back(domainPartLen);

        for (size_t j = 0; j < domainSplit[i].size(); j++){
            uint8_t domainSplitPartitionChar = domainSplit[i][j];
            domainBytes.push_back(domainSplitPartitionChar);
        }
    }
    //Add terminating byte
    domainBytes.push_back(0x00);

    uint8_t typeByte1 = static_cast<uint8_t>((type & 0xFF00) >> 8);
    uint8_t typeByte2 = static_cast<uint8_t>((type & 0x00FF));

    uint8_t classByte1 = static_cast<uint8_t>((className & 0xFF00) >> 8);
    uint8_t classByte2 = static_cast<uint8_t>((className & 0x00FF));

    return std::vector<uint8_t>{typeByte1,typeByte2,classByte1,classByte2};


}

std::vector<std::string> split (const std::string &s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss (s);
    std::string item;

    while (getline (ss, item, delim)) {
        result.push_back (item);
    }

    return result;
}