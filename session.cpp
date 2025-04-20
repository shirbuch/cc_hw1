#include <list>
#include <stdio.h>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include "session.h"
#include "utils.h"
#include "crypto_wrapper.h"


#ifdef WIN
#pragma warning(disable:4996) 
#endif // #ifdef WIN


static constexpr size_t MAX_CONTEXT_SIZE = 100;


Session::Session(const char* keyFilename, char* password, const char* certFilename, const char* rootCaFilename, const char* peerIdentity)
{
    _state = UNINITIALIZED_SESSION_STATE;

    _localSocket = new Socket(0);
    if (!_localSocket->valid())
    {
        return;
    }
    _pReferenceCounter = new ReferenceCounter();
    _pReferenceCounter->AddRef();

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = keyFilename;
    _privateKeyPassword = password;
    _localCertFilename = certFilename;
    _rootCaCertFilename = rootCaFilename;
    _expectedRemoteIdentityString = peerIdentity;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);
    _dhContext = NULL;
    memset(_localDhPublicKeyBuffer, 0, DH_KEY_SIZE_BYTES);
    memset(_remoteDhPublicKeyBuffer, 0, DH_KEY_SIZE_BYTES);
    memset(_sharedDhSecretBuffer, 0, DH_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


Session::Session(const Session& other)
{
    _state = UNINITIALIZED_SESSION_STATE;
    _pReferenceCounter = other._pReferenceCounter;
    _pReferenceCounter->AddRef();

    _localSocket = other._localSocket;

    _sessionId = 0;
    _outgoingMessageCounter = 0;
    _incomingMessageCounter = 0;

    // Init crypto part
    _privateKeyFilename = other._privateKeyFilename;
    _privateKeyPassword = other._privateKeyPassword;
    _localCertFilename = other._localCertFilename;
    _rootCaCertFilename = other._rootCaCertFilename;
    _expectedRemoteIdentityString = other._expectedRemoteIdentityString;
    memset(_sessionKey, 0, SYMMETRIC_KEY_SIZE_BYTES);
    _dhContext = NULL;
    memset(_localDhPublicKeyBuffer, 0, DH_KEY_SIZE_BYTES);
    memset(_remoteDhPublicKeyBuffer, 0, DH_KEY_SIZE_BYTES);
    memset(_sharedDhSecretBuffer, 0, DH_KEY_SIZE_BYTES);

    _state = INITIALIZED_SESSION_STATE;
}


void Session::closeSession()
{
    if (active())
    {
        ByteSmartPtr encryptedMessage = prepareEncryptedMessage(GOODBYE_SESSION_MESSAGE, NULL, 0);
        if (encryptedMessage != NULL)
        {
            sendMessageInternal(GOODBYE_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
            _state = GOODBYE_SESSION_MESSAGE;
        }
    }
}

void Session::destroySession()
{
    cleanDhData();
    if (_pReferenceCounter != NULL && _pReferenceCounter->Release() == 0)
    {
        delete _localSocket;
        _localSocket = NULL;
        delete _pReferenceCounter;
        _pReferenceCounter = NULL;

        if (_privateKeyPassword != NULL)
        {
            // we better clean it using some Utils function
            // ...
        }
    }
    else
    {
        _pReferenceCounter = NULL;
    }

    _state = DEACTIVATED_SESSION_STATE;
}


bool Session::active()
{
    return (_state == INITIALIZED_SESSION_STATE ||
        (_state >= FIRST_SESSION_MESSAGE_TYPE && _state <= LAST_SESSION_MESSAGE_TYPE));
}


void Session::setRemoteAddress(const char* remoteIpAddress, unsigned int remotePort) 
{
        memset(&(_remoteAddress), 0, sizeof(sockaddr_in));
        _remoteAddress.sin_family = AF_INET;
        _remoteAddress.sin_port = htons(remotePort);
        _remoteAddress.sin_addr.s_addr = inet_addr(remoteIpAddress);
}


void Session::prepareMessageHeader(MessageHeader* header, unsigned int type, size_t messageSize)
{
    header->sessionId = _sessionId;
    header->messageType = type;
    header->messageCounter =_outgoingMessageCounter;
    header->payloadSize = (unsigned int)messageSize;
}


bool Session::sendMessageInternal(unsigned int type, const BYTE* message, size_t messageSize)
{
    if (!active())
    {
        return false;
    }

    MessageHeader header;
    prepareMessageHeader(&header, type, messageSize);

    ByteSmartPtr messageBufferSmartPtr = concat(2, &header, sizeof(header), message, messageSize);
    if (messageBufferSmartPtr == NULL)
    {
        return false;
    }

    bool result = _localSocket->send(messageBufferSmartPtr, messageBufferSmartPtr.size(), &(_remoteAddress));
    if (result)
    {
        _outgoingMessageCounter++;
    }

    return result;
}


void Session::cleanDhData()
{
	CryptoWrapper::cleanDhContext(&_dhContext);
}


void Session::deriveMacKey(BYTE* macKeyBuffer)
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "MAC over certificate key %d", _sessionId) <= 0)
    {
        exit(0);
    }
    
    BYTE salt[32];
    memset(salt, _sessionId, sizeof(salt));

	if (!CryptoWrapper::deriveKey_HKDF_SHA256(salt, 32, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES, NULL, 0, macKeyBuffer, SYMMETRIC_KEY_SIZE_BYTES))
    {
        printf("deriveMacKey failed - Error deriving MAC key\n");
        cleanDhData();
    }
}


void Session::deriveSessionKey()
{
    char keyDerivationContext[MAX_CONTEXT_SIZE];
    if (sprintf_s(keyDerivationContext, MAX_CONTEXT_SIZE, "ENC session key %d", _sessionId) <= 0)
    {
        exit(0);
    }
    
    // Use a different salt value than MAC key, but still deterministic based on session ID
    // Adding 1 to session ID provides separation between MAC and encryption keys
    BYTE salt[32];
    memset(salt, _sessionId + 1, sizeof(salt));
    
    // Derive the session key using HKDF
    if (!CryptoWrapper::deriveKey_HKDF_SHA256(
            salt, 32,
            _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES,
            (BYTE*)keyDerivationContext, strlen(keyDerivationContext),
            _sessionKey, SYMMETRIC_KEY_SIZE_BYTES))
    {
        printf("deriveSessionKey failed - Error deriving session key\n");
        cleanDhData();
    }
}


ByteSmartPtr Session::prepareSigmaMessage(unsigned int messageType)
{
    if (messageType != 2 && messageType != 3)
    {
        return 0;
    }

    // we will be building the following message parts:
    // 1: my DH public key 
    // 2: My certificate (PEM)
    // 3: Signature over concatenated public keys with my permanenet private key
    // 4: MAC over my certificate with the shared MAC key

    // Init DH
    if (messageType == 2)
    {
        if (_dhContext != NULL)
        {
            printf("prepareDhMessage #%d - Error - DH context is not NULL\n", messageType);
            cleanDhData();
            return NULL;
        }
        if (!CryptoWrapper::startDh(&_dhContext, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("prepareDhMessage #%d - Error during startDh\n", messageType);
            cleanDhData();
            return NULL;
        }
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("prepareDhMessage #%d - Error during getDhSharedSecret\n", messageType);
            cleanDhData();
            return NULL;
        }
    }
    
    // get my certificate
    ByteSmartPtr certBufferSmartPtr = Utils::readBufferFromFile(_localCertFilename);
    if (certBufferSmartPtr == NULL)
    {
        printf("prepareDhMessage - Error reading certificate filename - %s\n", _localCertFilename);
        return NULL;
    }

    // get my private key for signing
    KeypairContext* privateKeyContext = NULL;
    if (!CryptoWrapper::readRSAKeyFromFile(_privateKeyFilename, _privateKeyPassword, &privateKeyContext))
    {
        printf("prepareDhMessage #%d - Error during readRSAKeyFromFile - %s\n", messageType, _privateKeyFilename);
        cleanDhData();
        return NULL;
    }

    ByteSmartPtr conacatenatedPublicKeysSmartPtr = concat(2, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (conacatenatedPublicKeysSmartPtr == NULL)
    {
        printf("prepareDhMessage #%d failed - Error concatenating public keys\n", messageType);
        cleanDhData();
        return NULL;
    }
    BYTE signature[SIGNATURE_SIZE_BYTES];
	if (!CryptoWrapper::signMessageRsa3072Pss((const BYTE*)conacatenatedPublicKeysSmartPtr, conacatenatedPublicKeysSmartPtr.size(), privateKeyContext, signature, SIGNATURE_SIZE_BYTES))
    {
        printf("prepareDhMessage #%d failed - Error signing message\n", messageType);
        cleanDhData();
        return NULL;
    }

    // Now we will calculate the MAC over my certificate
    BYTE macKeyBuffer[SYMMETRIC_KEY_SIZE_BYTES];
    // todo: same salt in both sides
    deriveMacKey(macKeyBuffer);
    BYTE calculatedMac[HMAC_SIZE_BYTES];
	if (!CryptoWrapper::hmac_SHA256((const BYTE*)macKeyBuffer, SYMMETRIC_KEY_SIZE_BYTES, (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(), calculatedMac, HMAC_SIZE_BYTES))
    {
        printf("prepareDhMessage #%d failed - Error calculating MAC\n", messageType);
        cleanDhData();
        Utils::secureCleanMemory(macKeyBuffer, SYMMETRIC_KEY_SIZE_BYTES);
        return NULL;
    }
	Utils::secureCleanMemory(macKeyBuffer, SYMMETRIC_KEY_SIZE_BYTES);

    // pack all of the parts together
    ByteSmartPtr messageToSend = packMessageParts(4, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, (BYTE*)certBufferSmartPtr, certBufferSmartPtr.size(), signature, SIGNATURE_SIZE_BYTES, calculatedMac, HMAC_SIZE_BYTES);
    Utils::secureCleanMemory(calculatedMac, HMAC_SIZE_BYTES);
    return messageToSend;
}

bool Session::verifySigmaMessage(unsigned int messageType, const BYTE* pPayload, size_t payloadSize)
{
    if (messageType != 2 && messageType != 3)
    {
        return 0;
    }

    unsigned int expectedNumberOfParts = 4;
    unsigned int partIndex = 0;

    // We are expecting 4 parts
    // 1: Remote public DH key (in message type 3 we will check that it equalss the value received in message type 1)
    // 2: Remote certificate (PEM) null terminated
    // 3: Signature over concatenated public keys (remote|local)
    // 4: MAC over remote certificate with the shared MAC key

    std::vector<MessagePart> parts;
    if (!unpackMessageParts(pPayload, payloadSize, parts) || parts.size() != expectedNumberOfParts)
    {
        printf("verifySigmaMessage #%d failed - number of message parts is wrong\n", messageType);
        return false;
    }

    const BYTE* inRemoteDhPublicKeyBuffer = parts[0].part;
    const MessagePart inCertBufferSmartPtrPart = parts[1];
    const MessagePart inSignaturePart = parts[2];
    const MessagePart inCalculatedMacPart = parts[3];

    // we will now verify if the received certificate belongs to the expected remote entity
	ByteSmartPtr cAcertBufferSmartPtr = Utils::readBufferFromFile(_rootCaCertFilename);
	if (cAcertBufferSmartPtr == NULL)
	{
		printf("Error reading certificate filename - %s\n", _rootCaCertFilename);
		return false;
	}
	if (!CryptoWrapper::checkCertificate(cAcertBufferSmartPtr, cAcertBufferSmartPtr.size(), inCertBufferSmartPtrPart.part, inCertBufferSmartPtrPart.partSize, _expectedRemoteIdentityString))
    {
        printf("verifySigmaMessage #%d failed - Error checking certificate\n", messageType);
        return false;
    }

    // Now we will calculate the shared secret
    if (messageType == 2)
    {
        memcpy_s(_remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, inRemoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
        if (!CryptoWrapper::getDhSharedSecret(_dhContext, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _sharedDhSecretBuffer, DH_KEY_SIZE_BYTES))
        {
            printf("prepareDhMessage #%d - Error during getDhSharedSecret\n", messageType);
            cleanDhData();
            return false;
        }
    }
    
    // now we will verify if the signature over the concatenated public keys is ok
    /// Get Public key from certificate
    KeypairContext* publicKeyContext = NULL;
    if (!CryptoWrapper::getPublicKeyFromCertificate(inCertBufferSmartPtrPart.part, inCertBufferSmartPtrPart.partSize, &publicKeyContext))
    {
        printf("verifySigmaMessage #%d failed - Error getting public key from certificate\n", messageType);
        cleanDhData();
        CryptoWrapper::cleanKeyContext(&publicKeyContext);
        return false;
    }
    // todo: verify that public key in certificate is the same as the one we received
    
    // Swiched placing of keys in the concatenated buffer to match the order of signing
    ByteSmartPtr conacatenatedPublicKeysSmartPtr = concat(2, _remoteDhPublicKeyBuffer, DH_KEY_SIZE_BYTES, _localDhPublicKeyBuffer, DH_KEY_SIZE_BYTES);
    if (conacatenatedPublicKeysSmartPtr == NULL)
    {
        printf("prepareDhMessage #%d failed - Error concatenating public keys\n", messageType);
        cleanDhData();
        return NULL;
    }
    
    /// Verify signature
    bool signatureIsOK = false;
	if (!CryptoWrapper::verifyMessageRsa3072Pss((const BYTE*)conacatenatedPublicKeysSmartPtr, conacatenatedPublicKeysSmartPtr.size(), publicKeyContext, inSignaturePart.part, inSignaturePart.partSize, &signatureIsOK))
    {
        printf("verifySigmaMessage #%d failed - Error verifying signature\n", messageType);
        cleanDhData();
        CryptoWrapper::cleanKeyContext(&publicKeyContext);
        return false;
    }
    CryptoWrapper::cleanKeyContext(&publicKeyContext);

    // Now we will verify the MAC over the certificate
    BYTE macKeyBuffer[SYMMETRIC_KEY_SIZE_BYTES];
    // todo: same salt in both sides
    deriveMacKey(macKeyBuffer);
    BYTE calculatedMac[HMAC_SIZE_BYTES];
	if (!CryptoWrapper::hmac_SHA256((const BYTE*)macKeyBuffer, SYMMETRIC_KEY_SIZE_BYTES, inCertBufferSmartPtrPart.part, inCertBufferSmartPtrPart.partSize, calculatedMac, HMAC_SIZE_BYTES))
    {
        printf("prepareDhMessage #%d failed - Error calculating MAC\n", messageType);
        cleanDhData();
        Utils::secureCleanMemory(macKeyBuffer, SYMMETRIC_KEY_SIZE_BYTES);
        return NULL;
    }
	Utils::secureCleanMemory(macKeyBuffer, SYMMETRIC_KEY_SIZE_BYTES);
    
    if (inCalculatedMacPart.partSize != HMAC_SIZE_BYTES)
    {
        printf("verifySigmaMessage #%d failed - Error MAC size is wrong\n", messageType);
        cleanDhData();
        return false;
    }
    if (memcmp(calculatedMac, inCalculatedMacPart.part, HMAC_SIZE_BYTES) != 0)
    {
        printf("verifySigmaMessage #%d failed - Error verifying MAC\n", messageType);
        cleanDhData();
        return false;
    }

    return true;
}


ByteSmartPtr Session::prepareEncryptedMessage(unsigned int messageType, const BYTE* message, size_t messageSize)
{
    // we will do a plain copy for now
    size_t encryptedMessageSize = messageSize;
    BYTE* ciphertext = (BYTE*)Utils::allocateBuffer(encryptedMessageSize);
    if (ciphertext == NULL)
    {
        return NULL;
    }

    memcpy_s(ciphertext, encryptedMessageSize, message, messageSize);

    ByteSmartPtr result(ciphertext, encryptedMessageSize);
    return result;
}


bool Session::decryptMessage(MessageHeader* header, BYTE* buffer, size_t* pPlaintextSize)
{
    // we will do a plain copy for now
    size_t ciphertextSize = header->payloadSize;
    size_t plaintextSize = ciphertextSize;
    

    if (pPlaintextSize != NULL)
    {
        *pPlaintextSize = plaintextSize;
    }

    return true;
}


bool Session::sendDataMessage(const BYTE* message, size_t messageSize)
{
    if (!active() || _state != DATA_SESSION_MESSAGE)
    {
        return false;
    }

    ByteSmartPtr encryptedMessage = prepareEncryptedMessage(DATA_SESSION_MESSAGE, message, messageSize);
    if (encryptedMessage == NULL)
    {
        return false;
    }

    return sendMessageInternal(DATA_SESSION_MESSAGE, encryptedMessage, encryptedMessage.size());
}


ByteSmartPtr Session::concat(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += messagePart.partSize;
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by the smart pointer logic)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    // copy the parts into the new buffer
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


ByteSmartPtr Session::packMessageParts(unsigned int numOfParts, ...)
{
    va_list args;
    va_start(args, numOfParts);
    size_t totalSize = 0;
    std::list<MessagePart> partsList;

    // build a list and count the desired size for buffer
    for (unsigned int i = 0; i < numOfParts; i++)
    {
        MessagePart messagePart;
        messagePart.part = va_arg(args, const BYTE*);
        messagePart.partSize = va_arg(args, unsigned int);
        totalSize += (messagePart.partSize + sizeof(size_t));
        partsList.push_back(messagePart);
    }
    va_end(args);

    // allocate required buffer size (will be released by caller's smart pointer)
    BYTE* buffer = (BYTE*)Utils::allocateBuffer(totalSize);
    if (buffer == NULL)
    {
        return NULL;
    }

    // copy the parts into the new buffer
    std::list<MessagePart>::iterator it = partsList.begin();
    BYTE* pos = buffer;
    size_t spaceLeft = totalSize;
    for (; it != partsList.end(); it++)
    {
        memcpy_s(pos, spaceLeft, (void*)&(it->partSize), sizeof(size_t));
        pos += sizeof(size_t);
        spaceLeft -= sizeof(size_t);
        memcpy_s(pos, spaceLeft, it->part, it->partSize);
        pos += it->partSize;
        spaceLeft -= it->partSize;
    }

    ByteSmartPtr result(buffer, totalSize);
    return result;
}


bool Session::unpackMessageParts(const BYTE* buffer, size_t bufferSize, std::vector<MessagePart>& result)
{
    std::list<MessagePart> partsList;
    size_t pos = 0;
    while (pos < bufferSize)
    {
        if (pos + sizeof(size_t) >= bufferSize)
        {
            return false;
        }

        size_t* partSize = (size_t*)(buffer + pos);
        pos += sizeof(size_t);
        if (*partSize == 0 || (pos + *partSize) > bufferSize)
            return false;

        MessagePart messagePart;
        messagePart.partSize = *partSize;
        messagePart.part = (buffer + pos);
        partsList.push_back(messagePart);
        pos += *partSize;
    }

    result.resize(partsList.size());
    unsigned int i = 0;
    for (std::list<MessagePart>::iterator it = partsList.begin(); it != partsList.end(); it++)
    {
        result[i].part = it->part;
        result[i].partSize = it->partSize;
        i++;
    }
    return true;
}















