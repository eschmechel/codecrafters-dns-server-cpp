#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <sstream>
#include <ctype.h>

std::vector<uint8_t> createDNSHeader ( uint16_t packetID, 
                                        int QRID,int OPCODE,int AA, int TC, int RD,
                                        int RA, int Z, int AD, int CD, int RCODE,
                                        uint16_t numOfQuestions,
                                        uint16_t numOfAnswers,
                                        uint16_t numOfAuthorityRRs,
                                        uint16_t numOfAdditionalRRs
                                    );

std::vector<uint8_t> createDNSQuestion(std::string domainName, uint16_t type, uint16_t className);

std::vector<uint8_t> createDNSAnswer(std::string domainName,uint16_t type, uint16_t className, uint32_t TTL, uint16_t RDLENGTH, std::string RDATA);

std::vector<uint8_t> encodeDomainName(const std::string domainName);

std::vector<std::string> split (const std::string &s, char delim);

void parseHeader(const char* &buffer, uint16_t &packetID, int &QRID,int &OPCODE,int &AA, int &TC, int &RD, int &RA, int &Z, int &AD, int &CD, int &RCODE,
                                        uint16_t &numOfQuestions, uint16_t &numOfAnswers, uint16_t &numOfAuthorityRRs, uint16_t &numOfAdditionalRRs);

void parseQuestion(const char* &buffer,std::string &DomainName,uint16_t typeByte, uint16_t &classByte);


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

        std::uint16_t packetID, numOfQuestions, numOfAnswers, numOfAuthorityRRs, numOfAdditionalRRs; 
        int QRID, OPCODE, AA, TC, RD, RA, Z, AD, CD, RCODE; 
        const char* bufPtr = buffer;
        parseHeader(bufPtr,packetID,QRID,OPCODE, AA,TC,RD,RA,Z,AD,CD,RCODE,numOfQuestions,numOfAnswers,numOfAuthorityRRs,numOfAdditionalRRs);

        std::string domainName;
        uint16_t className,typeName;
        parseQuestion(bufPtr,domainName,typeName,className);

        // Create an empty response
        char response[1] = { '\0' };
        auto DNSHeader = createDNSHeader(packetID,1,OPCODE,0,0,RD,0,0,0,0,4,1,1,0,0);
        auto DNSQuestion = createDNSQuestion(domainName,typeName,className);
        auto DNSAnswer = createDNSAnswer(domainName,typeName,className,60,4,"8.8.8.8");
        std::vector<uint8_t> dnsMessage = DNSHeader;
        dnsMessage.insert(dnsMessage.end(),DNSQuestion.begin(),DNSQuestion.end());
        dnsMessage.insert(dnsMessage.end(),DNSAnswer.begin(),DNSAnswer.end());

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

    std::vector<uint8_t>questionBytes = encodeDomainName(domainName);

    uint8_t typeByte1 = static_cast<uint8_t>((type & 0xFF00) >> 8);
    uint8_t typeByte2 = static_cast<uint8_t>((type & 0x00FF));

    uint8_t classByte1 = static_cast<uint8_t>((className & 0xFF00) >> 8);
    uint8_t classByte2 = static_cast<uint8_t>((className & 0x00FF));

    // Append type and class to domain bytes
    questionBytes.push_back(typeByte1);
    questionBytes.push_back(typeByte2);
    questionBytes.push_back(classByte1);
    questionBytes.push_back(classByte2);

    return questionBytes;


}

std::vector<uint8_t> createDNSAnswer(std::string domainName,uint16_t type, uint16_t className, uint32_t TTL, uint16_t RDLENGTH, std::string RDATA){
    //Domain
    std::vector<uint8_t> answerBytes = encodeDomainName(domainName);

    //Type
    answerBytes.push_back(static_cast<uint8_t>((type & 0xFF00) >> 8));
    answerBytes.push_back(static_cast<uint8_t>((type & 0x00FF)));

    //ClassName
    answerBytes.push_back(static_cast<uint8_t>((className & 0xFF00) >> 8));
    answerBytes.push_back(static_cast<uint8_t>((className & 0x00FF)));

    //TTL
    answerBytes.push_back(static_cast<std::uint8_t>((TTL >> 24) & 0xFF));
    answerBytes.push_back(static_cast<std::uint8_t>((TTL >> 16) & 0xFF));
    answerBytes.push_back(static_cast<std::uint8_t>((TTL >>  8) & 0xFF));
    answerBytes.push_back(static_cast<std::uint8_t>( TTL        & 0xFF));

    //RDLENGTH
    answerBytes.push_back(static_cast<uint8_t>((RDLENGTH & 0xFF00) >> 8));
    answerBytes.push_back(static_cast<uint8_t>((RDLENGTH & 0x00FF)));

    //Data
    std::vector<std::string> splitIP = split(RDATA,'.');
    for (std::string str: splitIP){
        uint8_t currentNum = std::stoi(str);
        answerBytes.push_back(currentNum);
    }
    return answerBytes;
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

std::vector<uint8_t> encodeDomainName(const std::string domainName){
    std::vector<std::string> domainSplit = split(domainName, '.');

    std::vector<uint8_t>questionBytes = {};
    for (size_t i = 0; i < domainSplit.size(); i++){
        uint8_t domainPartLen = domainSplit[i].size();
        questionBytes.push_back(domainPartLen);

        for (size_t j = 0; j < domainSplit[i].size(); j++){
            uint8_t domainSplitPartitionChar = (char)domainSplit[i][j];
            questionBytes.push_back(domainSplitPartitionChar);
        }
    }
    //Add terminating byte
    questionBytes.push_back(0x00);
    return questionBytes;
}

void parseHeader(const char* &buffer, uint16_t &packetID, int &QRID,int &OPCODE,int &AA, int &TC, int &RD, int &RA, int &Z, int &AD, int &CD, int &RCODE,
                                        uint16_t &numOfQuestions, uint16_t &numOfAnswers, uint16_t &numOfAuthorityRRs, uint16_t &numOfAdditionalRRs){
    std::vector<std::uint8_t> header;
    for (int i = 0; i < 12; i++){
        header.push_back(static_cast<std::uint8_t>(*(buffer++)));
    }

    packetID = ((std::uint16_t)header[0] << 8) | header[1];
    //Isolate individual bits
    QRID=   (header[2] >> 7 ) & 1;//bit 1
    OPCODE= (header[2] >>3) &0x0F;//bit2,3,4,5,
    AA=     (header[2] >> 2) & 1;
    TC=     (header[2] >> 1) & 1;
    RD=     (header[2] >> 0) & 1;

    RA=     (header[3] >> 7 ) & 1;
    Z=      (header[3] >> 6 ) & 1;
    AD=     (header[3] >> 5 ) & 1;
    CD=     (header[3] >> 4 ) & 1;
    RCODE=  (header[3] >> 0) &0x0F;

    numOfQuestions =        ((std::uint16_t)header[4] << 8) | header[5];
    numOfAnswers =          ((std::uint16_t)header[6] << 8) | header[7];
    numOfAuthorityRRs =     ((std::uint16_t)header[8] << 8) | header[9];
    numOfAdditionalRRs =    ((std::uint16_t)header[10] << 8) | header[11];
}

void parseQuestion(const char* &buffer,std::string &DomainName,uint16_t typeByte, uint16_t &classByte){

    buffer+=11;//Get beyond header
    while (buffer!= nullptr){
        if (!isdigit(*buffer)){
            DomainName+= *buffer;
        }else{
            DomainName += ".";
        }
        buffer++;
    }
    buffer++;//Get beyond null byte

    typeByte = ((std::uint16_t)*buffer << 8) | (std::uint8_t)*(++buffer);

    classByte = ((std::uint16_t)*(++buffer) << 8) | (std::uint8_t)*(++buffer);

}