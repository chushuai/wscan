package message

import (
	"encoding/binary"
	"net"

	"github.com/projectdiscovery/n3iwf/pkg/logger"
)

func (ikeMessage *IKEMessage) BuildIKEHeader(
	initiatorSPI uint64,
	responsorSPI uint64,
	exchangeType uint8,
	flags uint8,
	messageID uint32,
) {
	ikeMessage.InitiatorSPI = initiatorSPI
	ikeMessage.ResponderSPI = responsorSPI
	ikeMessage.Version = 0x20
	ikeMessage.ExchangeType = exchangeType
	ikeMessage.Flags = flags
	ikeMessage.MessageID = messageID
}

func (container *IKEPayloadContainer) Reset() {
	*container = nil
}

func (container *IKEPayloadContainer) BuildNotification(
	protocolID uint8,
	notifyMessageType uint16,
	spi []byte,
	notificationData []byte,
) {
	notification := new(Notification)
	notification.ProtocolID = protocolID
	notification.NotifyMessageType = notifyMessageType
	notification.SPI = append(notification.SPI, spi...)
	notification.NotificationData = append(notification.NotificationData, notificationData...)
	*container = append(*container, notification)
}

func (container *IKEPayloadContainer) BuildCertificate(certificateEncode uint8, certificateData []byte) {
	certificate := new(Certificate)
	certificate.CertificateEncoding = certificateEncode
	certificate.CertificateData = append(certificate.CertificateData, certificateData...)
	*container = append(*container, certificate)
}

func (container *IKEPayloadContainer) BuildEncrypted(nextPayload IKEPayloadType, encryptedData []byte) *Encrypted {
	encrypted := new(Encrypted)
	encrypted.NextPayload = uint8(nextPayload)
	encrypted.EncryptedData = append(encrypted.EncryptedData, encryptedData...)
	*container = append(*container, encrypted)
	return encrypted
}

func (container *IKEPayloadContainer) BUildKeyExchange(diffiehellmanGroup uint16, keyExchangeData []byte) {
	keyExchange := new(KeyExchange)
	keyExchange.DiffieHellmanGroup = diffiehellmanGroup
	keyExchange.KeyExchangeData = append(keyExchange.KeyExchangeData, keyExchangeData...)
	*container = append(*container, keyExchange)
}

func (container *IKEPayloadContainer) BuildIdentificationInitiator(idType uint8, idData []byte) {
	identification := new(IdentificationInitiator)
	identification.IDType = idType
	identification.IDData = append(identification.IDData, idData...)
	*container = append(*container, identification)
}

func (container *IKEPayloadContainer) BuildIdentificationResponder(idType uint8, idData []byte) {
	identification := new(IdentificationResponder)
	identification.IDType = idType
	identification.IDData = append(identification.IDData, idData...)
	*container = append(*container, identification)
}

func (container *IKEPayloadContainer) BuildAuthentication(authenticationMethod uint8, authenticationData []byte) {
	authentication := new(Authentication)
	authentication.AuthenticationMethod = authenticationMethod
	authentication.AuthenticationData = append(authentication.AuthenticationData, authenticationData...)
	*container = append(*container, authentication)
}

func (container *IKEPayloadContainer) BuildConfiguration(configurationType uint8) *Configuration {
	configuration := new(Configuration)
	configuration.ConfigurationType = configurationType
	*container = append(*container, configuration)
	return configuration
}

func (container *ConfigurationAttributeContainer) Reset() {
	*container = nil
}

func (container *ConfigurationAttributeContainer) BuildConfigurationAttribute(
	attributeType uint16,
	attributeValue []byte,
) {
	configurationAttribute := new(IndividualConfigurationAttribute)
	configurationAttribute.Type = attributeType
	configurationAttribute.Value = append(configurationAttribute.Value, attributeValue...)
	*container = append(*container, configurationAttribute)
}

func (container *IKEPayloadContainer) BuildNonce(nonceData []byte) {
	nonce := new(Nonce)
	nonce.NonceData = append(nonce.NonceData, nonceData...)
	*container = append(*container, nonce)
}

func (container *IKEPayloadContainer) BuildTrafficSelectorInitiator() *TrafficSelectorInitiator {
	trafficSelectorInitiator := new(TrafficSelectorInitiator)
	*container = append(*container, trafficSelectorInitiator)
	return trafficSelectorInitiator
}

func (container *IKEPayloadContainer) BuildTrafficSelectorResponder() *TrafficSelectorResponder {
	trafficSelectorResponder := new(TrafficSelectorResponder)
	*container = append(*container, trafficSelectorResponder)
	return trafficSelectorResponder
}

func (container *IndividualTrafficSelectorContainer) Reset() {
	*container = nil
}

func (container *IndividualTrafficSelectorContainer) BuildIndividualTrafficSelector(
	tsType uint8,
	ipProtocolID uint8,
	startPort uint16,
	endPort uint16,
	startAddr []byte,
	endAddr []byte,
) {
	trafficSelector := new(IndividualTrafficSelector)
	trafficSelector.TSType = tsType
	trafficSelector.IPProtocolID = ipProtocolID
	trafficSelector.StartPort = startPort
	trafficSelector.EndPort = endPort
	trafficSelector.StartAddress = append(trafficSelector.StartAddress, startAddr...)
	trafficSelector.EndAddress = append(trafficSelector.EndAddress, endAddr...)
	*container = append(*container, trafficSelector)
}

func (container *IKEPayloadContainer) BuildSecurityAssociation() *SecurityAssociation {
	securityAssociation := new(SecurityAssociation)
	*container = append(*container, securityAssociation)
	return securityAssociation
}

func (container *ProposalContainer) Reset() {
	*container = nil
}

func (container *ProposalContainer) BuildProposal(proposalNumber uint8, protocolID uint8, spi []byte) *Proposal {
	proposal := new(Proposal)
	proposal.ProposalNumber = proposalNumber
	proposal.ProtocolID = protocolID
	proposal.SPI = append(proposal.SPI, spi...)
	*container = append(*container, proposal)
	return proposal
}

func (container *IKEPayloadContainer) BuildDeletePayload(
	protocolID uint8, SPISize uint8, numberOfSPI uint16, SPIs []byte,
) {
	deletePayload := new(Delete)
	deletePayload.ProtocolID = protocolID
	deletePayload.SPISize = SPISize
	deletePayload.NumberOfSPI = numberOfSPI
	deletePayload.SPIs = SPIs
	*container = append(*container, deletePayload)
}

func (container *TransformContainer) Reset() {
	*container = nil
}

func (container *TransformContainer) BuildTransform(
	transformType uint8,
	transformID uint16,
	attributeType *uint16,
	attributeValue *uint16,
	variableLengthAttributeValue []byte,
) {
	transform := new(Transform)
	transform.TransformType = transformType
	transform.TransformID = transformID
	if attributeType != nil {
		transform.AttributePresent = true
		transform.AttributeType = *attributeType
		if attributeValue != nil {
			transform.AttributeFormat = AttributeFormatUseTV
			transform.AttributeValue = *attributeValue
		} else if len(variableLengthAttributeValue) != 0 {
			transform.AttributeFormat = AttributeFormatUseTLV
			transform.VariableLengthAttributeValue = append(transform.VariableLengthAttributeValue,
				variableLengthAttributeValue...)
		} else {
			return
		}
	} else {
		transform.AttributePresent = false
	}
	*container = append(*container, transform)
}

func (container *IKEPayloadContainer) BuildEAP(code uint8, identifier uint8) *EAP {
	eap := new(EAP)
	eap.Code = code
	eap.Identifier = identifier
	*container = append(*container, eap)
	return eap
}

func (container *IKEPayloadContainer) BuildEAPSuccess(identifier uint8) {
	eap := new(EAP)
	eap.Code = EAPCodeSuccess
	eap.Identifier = identifier
	*container = append(*container, eap)
}

func (container *IKEPayloadContainer) BuildEAPfailure(identifier uint8) {
	eap := new(EAP)
	eap.Code = EAPCodeFailure
	eap.Identifier = identifier
	*container = append(*container, eap)
}

func (container *EAPTypeDataContainer) BuildEAPExpanded(vendorID uint32, vendorType uint32, vendorData []byte) {
	eapExpanded := new(EAPExpanded)
	eapExpanded.VendorID = vendorID
	eapExpanded.VendorType = vendorType
	eapExpanded.VendorData = append(eapExpanded.VendorData, vendorData...)
	*container = append(*container, eapExpanded)
}

func (container *IKEPayloadContainer) BuildEAP5GStart(identifier uint8) {
	eap := container.BuildEAP(EAPCodeRequest, identifier)
	eap.EAPTypeData.BuildEAPExpanded(VendorID3GPP, VendorTypeEAP5G, []byte{EAP5GType5GStart, EAP5GSpareValue})
}

func (container *IKEPayloadContainer) BuildEAP5GNAS(identifier uint8, nasPDU []byte) {
	if len(nasPDU) == 0 {
		logger.IKELog.Error("BuildEAP5GNAS(): NASPDU is nil")
		return
	}

	header := make([]byte, 4)

	// Message ID
	header[0] = EAP5GType5GNAS
	// NASPDU length (2 octets)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(nasPDU)))
	vendorData := append(header, nasPDU...)

	eap := container.BuildEAP(EAPCodeRequest, identifier)
	eap.EAPTypeData.BuildEAPExpanded(VendorID3GPP, VendorTypeEAP5G, vendorData)
}

func (container *IKEPayloadContainer) BuildNotify5G_QOS_INFO(
	pduSessionID uint8,
	qfiList []uint8,
	isDefault bool,
	isDSCPSpecified bool,
	DSCP uint8,
) {
	notifyData := make([]byte, 1) // For length
	// Append PDU session ID
	notifyData = append(notifyData, pduSessionID)
	// Append QFI list length
	notifyData = append(notifyData, uint8(len(qfiList)))
	// Append QFI list
	notifyData = append(notifyData, qfiList...)
	// Append default and differentiated service flags
	var defaultAndDifferentiatedServiceFlags uint8
	if isDefault {
		defaultAndDifferentiatedServiceFlags |= NotifyType5G_QOS_INFOBitDCSICheck
	}
	if isDSCPSpecified {
		defaultAndDifferentiatedServiceFlags |= NotifyType5G_QOS_INFOBitDSCPICheck
	}

	notifyData = append(notifyData, defaultAndDifferentiatedServiceFlags)
	if isDSCPSpecified {
		notifyData = append(notifyData, DSCP)
	}

	// Assign length
	notifyData[0] = uint8(len(notifyData))

	container.BuildNotification(TypeNone, Vendor3GPPNotifyType5G_QOS_INFO, nil, notifyData)
}

func (container *IKEPayloadContainer) BuildNotifyNAS_IP4_ADDRESS(nasIPAddr string) {
	if nasIPAddr == "" {
		return
	} else {
		ipAddrByte := net.ParseIP(nasIPAddr).To4()
		container.BuildNotification(TypeNone, Vendor3GPPNotifyTypeNAS_IP4_ADDRESS, nil, ipAddrByte)
	}
}

func (container *IKEPayloadContainer) BuildNotifyUP_IP4_ADDRESS(upIPAddr string) {
	if upIPAddr == "" {
		return
	} else {
		ipAddrByte := net.ParseIP(upIPAddr).To4()
		container.BuildNotification(TypeNone, Vendor3GPPNotifyTypeUP_IP4_ADDRESS, nil, ipAddrByte)
	}
}

func (container *IKEPayloadContainer) BuildNotifyNAS_TCP_PORT(port uint16) {
	if port == 0 {
		return
	} else {
		portData := make([]byte, 2)
		binary.BigEndian.PutUint16(portData, port)
		container.BuildNotification(TypeNone, Vendor3GPPNotifyTypeNAS_TCP_PORT, nil, portData)
	}
}
