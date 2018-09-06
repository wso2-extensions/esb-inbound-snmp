/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.inbound.snmp;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.UUIDGenerator;
import org.apache.axis2.builder.Builder;
import org.apache.axis2.builder.BuilderUtil;
import org.apache.axis2.builder.SOAPBuilder;
import org.apache.axis2.transport.TransportUtils;
import org.apache.commons.io.input.AutoCloseInputStream;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseException;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.mediators.base.SequenceMediator;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.MessageDispatcherImpl;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.TcpAddress;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;
import org.wso2.carbon.inbound.endpoint.protocol.generic.GenericEventBasedConsumer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * SNMP inbound endpoint is used to listen and consume messages from SNMP agent via WSO2 ESB.
 */
public class SNMPListeningConsumer extends GenericEventBasedConsumer implements CommandResponder {

    private static final Log logger = LogFactory.getLog(SNMPListeningConsumer.class);
    private Address listenAddress;
    private Snmp snmp = null;
    private ThreadPool threadPool;
    private String verifiedSnmpVersion;

    /**
     * @param properties            a persistent set of properties for InboundEndpoint.
     * @param name                  name of the inbound endpoint
     * @param synapseEnvironment    synapse environment
     * @param injectingSeq          name of the sequence message that should be injected
     * @param onErrorSeq            name of the fault sequence that should be invoked in case of failure
     * @param coordination          this parameter is only applicable in a cluster environment
     * @param sequential            The behavior when executing the given sequence.
     */
    public SNMPListeningConsumer(Properties properties, String name, SynapseEnvironment synapseEnvironment,
                                 String injectingSeq, String onErrorSeq, boolean coordination, boolean sequential) {

        super(properties, name, synapseEnvironment, injectingSeq, onErrorSeq, coordination, sequential);
        logger.info(String.format("Starting to load the SNMP Inbound Endpoint %s", name));

        String host = properties.getProperty(SNMPConstants.HOST);
        int port;
        String snmpVersion = properties.getProperty(SNMPConstants.SNMP_VERSION);
        boolean isTCP = Boolean.parseBoolean(properties.getProperty(SNMPConstants.IS_TCP));

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Starting to load the SNMP Properties for %s", name));
        }

        if (StringUtils.isEmpty(host)) {
            throw new SynapseException(String.format("IP address of the SNMP is not set for %s ", name));
        }

        if (StringUtils.isEmpty(properties.getProperty(SNMPConstants.PORT))) {
            throw new SynapseException(String.format("Port to access the %s is not set for %s ", host , name));
        } else {
            port = Integer.parseInt(properties.getProperty(SNMPConstants.PORT));
        }

        if (snmpVersion.equals(SNMPConstants.SNMP_VERSION2C) || snmpVersion.equals(SNMPConstants.SNMP_VERSION1)) {
            this.verifiedSnmpVersion = snmpVersion;
        } else if (StringUtils.isEmpty(snmpVersion)) {
            this.verifiedSnmpVersion = SNMPConstants.SNMP_VERSION2C;
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug(SNMPConstants.SNMP_MESSAGE);
            }
            throw new SynapseException(SNMPConstants.SNMP_MESSAGE);
        }
        if (isTCP) {
            listenAddress = GenericAddress.parse(System.getProperty(
                    "snmp4j.listenAddress", "tcp:" + host + SNMPConstants.COMBINER + port));
        } else {
            listenAddress = GenericAddress.parse(System.getProperty(
                    "snmp4j.listenAddress", "udp:" + host + SNMPConstants.COMBINER + port));
        }
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Loaded the SNMP Parameters with Host : %s , Port : %s for %s "
                    , host, port, name));
        }
        logger.info(String.format("Initialized the SNMP inbound consumer %s " , name));
    }

    /**
     * Create connection with SNMP agent and listen to retrieve the messages..
     */
    public void listen() {

        try {
            TransportMapping<?> transport;
            threadPool = ThreadPool.create(name + "trap", 10);
            MultiThreadedMessageDispatcher dispatcher = new MultiThreadedMessageDispatcher(threadPool,
                    new MessageDispatcherImpl());
            if (listenAddress instanceof UdpAddress) {
                transport = new DefaultUdpTransportMapping((UdpAddress) listenAddress);
            } else {
                transport = new DefaultTcpTransportMapping((TcpAddress) listenAddress);
            }
            snmp = new Snmp(dispatcher, transport);
            if (verifiedSnmpVersion.equals(SNMPConstants.SNMP_VERSION2C)) {
                snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());
                SecurityProtocols.getInstance().addPrivacyProtocol(new PrivAES192());
            } else {
                SecurityProtocols.getInstance().addDefaultProtocols();
                snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
            }
            snmp.listen();
            snmp.addCommandResponder(this);
        } catch (IOException e) {
            throw new SynapseException(String.format("Error occurred while creating a transport from the listening " +
                            "address: %s ", listenAddress));
        }
    }

    /**
     * This method used to process the retrieve message and inject according to the registered handler.
     * @param cmdRespEvent a CommandResponderEvent with the decoded incoming PDU as dispatched to
     *                     this method call by the associated message dispatcher.
     */
    @Override
    public void processPdu(CommandResponderEvent cmdRespEvent) {

        if (logger.isDebugEnabled()) {
            logger.debug("Received PDU...");
        }
        MessageContext msgCtx;
        msgCtx = createMessageContext();
        msgCtx.setProperty("Security_Level", cmdRespEvent.getSecurityLevel());
        msgCtx.setProperty("Security_Model", cmdRespEvent.getSecurityModel());
        msgCtx.setProperty("Security_Name", cmdRespEvent.getSecurityName());
        msgCtx.setProperty("Max_Size_Response_PDU", cmdRespEvent.getMaxSizeResponsePDU());
        msgCtx.setProperty("Pdu_Handle", cmdRespEvent.getPduHandle());
        msgCtx.setProperty("State_Reference", cmdRespEvent.getStateReference());
        msgCtx.setProperty("Tm_State_Reference", cmdRespEvent.getTmStateReference());
        msgCtx.setProperty("Peer_Address", cmdRespEvent.getPeerAddress().toString());
        msgCtx.setProperty("PDU_Dispatcher", cmdRespEvent.getMessageDispatcher());
        msgCtx.setProperty("PDU_Processing_Model", cmdRespEvent.getMessageProcessingModel());
        msgCtx.setProperty("PDU_Is_Processed", cmdRespEvent.isProcessed());
        msgCtx.setProperty("Source", cmdRespEvent.getSource());
        msgCtx.setProperty("PDU_Error_Index", cmdRespEvent.getPDU().getErrorIndex());
        msgCtx.setProperty("PDU_Error_Status", cmdRespEvent.getPDU().getErrorStatus());
        msgCtx.setProperty("PDU_RequestID", cmdRespEvent.getPDU().getRequestID().getValue());
        msgCtx.setProperty("PDU_Error_Status_Text", cmdRespEvent.getPDU().getErrorStatusText());
        msgCtx.setProperty("PDU_NonRepeaters", cmdRespEvent.getPDU().getNonRepeaters());
        msgCtx.setProperty("PDU_BER_Length", cmdRespEvent.getPDU().getBERLength());
        msgCtx.setProperty("PDU_BER_Payload_Length", cmdRespEvent.getPDU().getBERPayloadLength());
        msgCtx.setProperty("Listen_Address", cmdRespEvent.getTransportMapping().getListenAddress().toString());
        msgCtx.setProperty("Max_Inbound_Message_Size", cmdRespEvent.getTransportMapping().getMaxInboundMessageSize());
        msgCtx.setProperty("PDU_Type", cmdRespEvent.getPDU().getType());

        injectMessage(String.valueOf(cmdRespEvent.getPDU().getVariableBindings()), msgCtx);
    }

    /**
     * Close the connection with the SNMP Agent and stop all the threads.
     */
    public void destroy() {

        try {
            if (snmp != null) {
                snmp.close();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("The SNMP connection has been shutdown! for %s", name));
                }
            }
            if (threadPool != null) {
                threadPool.stop();
            }
        } catch (IOException e) {
            throw new SynapseException("Error occurred while shutdown the SNMP connection.");
        }
    }

    /**
     * This method injects a new message into the Synapse engine.
     * @param strMessage message for PDU.
     * @param msgCtx Synapse MessageContext to be sent
     */
    private void injectMessage(String strMessage, MessageContext msgCtx) {

        AutoCloseInputStream in = new AutoCloseInputStream(new ByteArrayInputStream(strMessage.getBytes()));
        try {
            if (logger.isDebugEnabled()) {
                logger.debug(String.format("Processed Custom inbound EP Message of Content-type : %s for %s "
                        , SNMPConstants.CONTENT_TYPE, name));
            }
            org.apache.axis2.context.MessageContext axis2MsgCtx = ((Axis2MessageContext) msgCtx)
                    .getAxis2MessageContext();
            Builder builder;
            if (StringUtils.isEmpty(SNMPConstants.CONTENT_TYPE)) {
                logger.debug(String.format("No content type specified. Using SOAP builder for %s ", name));
                builder = new SOAPBuilder();
            } else {
                String type = SNMPConstants.CONTENT_TYPE;
                builder = BuilderUtil.getBuilderFromSelector(type, axis2MsgCtx);
                if (builder == null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("No message builder found for type %s .Falling back to SOAP %s .",
                                type, name));
                    }
                    builder = new SOAPBuilder();
                }
            }
            OMElement documentElement = builder.processDocument(in, SNMPConstants.CONTENT_TYPE, axis2MsgCtx);
            msgCtx.setEnvelope(TransportUtils.createSOAPEnvelope(documentElement));
            if (this.injectingSeq == null || "".equals(this.injectingSeq)) {
                logger.error(String.format("Sequence name not specified. Sequence : %s ", this.injectingSeq));
                return;
            }
            SequenceMediator seq = (SequenceMediator) this.synapseEnvironment.getSynapseConfiguration()
                    .getSequence(this.injectingSeq);
            if (seq != null) {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("injecting message to sequence : %s ", this.injectingSeq));
                }
                seq.setErrorHandler(this.onErrorSeq);
                if (!seq.isInitialized()) {
                    seq.init(this.synapseEnvironment);
                }
                this.synapseEnvironment.injectInbound(msgCtx, seq, this.sequential);
            } else {
                logger.error(String.format("Sequence: %s not found %s ", this.injectingSeq, name));
            }
        } catch (Exception e) {
            throw new SynapseException("Error while processing the SNMP Message ", e);
        }
    }

    /**
     * Create the message context.
     */
    private MessageContext createMessageContext() {

        MessageContext msgCtx = this.synapseEnvironment.createMessageContext();
        org.apache.axis2.context.MessageContext axis2MsgCtx = ((Axis2MessageContext) msgCtx).getAxis2MessageContext();
        axis2MsgCtx.setServerSide(true);
        axis2MsgCtx.setMessageID(UUIDGenerator.getUUID());
        return msgCtx;
    }
}
