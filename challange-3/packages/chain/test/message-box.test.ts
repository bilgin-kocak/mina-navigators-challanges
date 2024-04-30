import { TestingAppChain } from "@proto-kit/sdk";
import { CircuitString, PrivateKey, PublicKey } from "o1js";
import { log } from "@proto-kit/common";
import { AgentCode, AgentDetails, AgentId, Message, MessageBox, MessageNumber, MessageText } from "../src/message-box";

log.setLevel("error");

describe("messagebox tests", () => {
  let appChain = TestingAppChain.fromRuntime({
    MessageBox,
  });
  let agentWL: Map<AgentId, AgentDetails>;
  let agentPK: PrivateKey;
  let agentPubKey: PublicKey;
  let messageBox: MessageBox;


  beforeEach(async () => {
    appChain = TestingAppChain.fromRuntime({
      MessageBox,
    });

    agentWL = new Map([[
      new AgentId(7),
      new AgentDetails({
        lastMessageNumber: new MessageNumber(0),
        securityCode: AgentCode.fromString("A7")
      })
    ]])

    appChain.configurePartial({
      Runtime: {
        MessageBox: {agentWL},
        Balances: {}
      },
    });

    await appChain.start();

    agentPK = PrivateKey.random();
    agentPubKey = agentPK.toPublicKey();

    appChain.setSigner(agentPK);

    messageBox = appChain.runtime.resolve("MessageBox");
  });

  it("should update the state on a valid message", async () => {
    const agentId: AgentId = agentWL.keys().next().value;

    const newMessage: Message = {
      details: {
        agentId,
        text: MessageText.fromString("Hello World!"),
        securityCode: agentWL.get(agentId)!.securityCode
      },
      messageNumber: new MessageNumber(1)
    };

    let block = await appChain.produceBlock();
    let message = await appChain.query.runtime.MessageBox.agents.get(agentId);

    // agent does not exist in the state
    expect(message?.lastMessageNumber.equals(new MessageNumber(0)).toBoolean()).toBe(undefined);

    const tx1 = await appChain.transaction(agentPubKey, () => {
      messageBox.processMessage(newMessage)
    });

    await tx1.sign();
    await tx1.send();

    block = await appChain.produceBlock();

    message = await appChain.query.runtime.MessageBox.agents.get(agentId);

    expect(block?.transactions[0].status.toBoolean()).toBe(true);
    expect(message?.lastMessageNumber.equals(new MessageNumber(1)).toBoolean()).toBe(true);
  }, 1_000_000);

  it("should fail for unexisting agent", async () => {
    const agentId: AgentId = new AgentId(8);

    const newMessage: Message = {
      details: {
        agentId,
        text: MessageText.fromString("Hello World!"),
        securityCode: AgentCode.fromString("A8")
      },
      messageNumber: new MessageNumber(1)
    };

    let block = await appChain.produceBlock();
    let message = await appChain.query.runtime.MessageBox.agents.get(agentId);

    // agent does not exist in the state
    expect(message?.lastMessageNumber.equals(new MessageNumber(0)).toBoolean()).toBe(undefined);

    const tx1 = await appChain.transaction(agentPubKey, () => {
      messageBox.processMessage(newMessage)
    });

    await tx1.sign();
    await tx1.send();

    block = await appChain.produceBlock();

    message = await appChain.query.runtime.MessageBox.agents.get(agentId);

    expect(block?.transactions[0].status.toBoolean()).toBe(false);
  }, 1_000_000);

  it("should fail with invalid security code", async () => {
    const agentId: AgentId = agentWL.keys().next().value;

    const newMessage: Message = {
      details: {
        agentId,
        text: MessageText.fromString("Hello World!"),
        securityCode: AgentCode.fromString("A8")
      },
      messageNumber: new MessageNumber(1)
    };

    let block = await appChain.produceBlock();
    let message = await appChain.query.runtime.MessageBox.agents.get(agentId);

    // agent does not exist in the state
    expect(message?.lastMessageNumber.equals(new MessageNumber(0)).toBoolean()).toBe(undefined);

    const tx1 = await appChain.transaction(agentPubKey, () => {
      messageBox.processMessage(newMessage)
    });

    await tx1.sign();
    await tx1.send();

    block = await appChain.produceBlock();

    message = await appChain.query.runtime.MessageBox.agents.get(agentId);

    expect(block?.transactions[0].status.toBoolean()).toBe(false);
  }, 1_000_000);

  it("should fail with invalid message length", async () => {
    const agentId: AgentId = agentWL.keys().next().value;

    const newMessage: Message = {
      details: {
        agentId,
        text: new MessageText({ text: CircuitString.fromString("Hello World") }),
        securityCode: AgentCode.fromString("A7")
      },
      messageNumber: new MessageNumber(1)
    };

    let block = await appChain.produceBlock();
    let message = await appChain.query.runtime.MessageBox.agents.get(agentId);

    // agent does not exist in the state
    expect(message?.lastMessageNumber.equals(new MessageNumber(0)).toBoolean()).toBe(undefined);

    const tx1 = await appChain.transaction(agentPubKey, () => {
      messageBox.processMessage(newMessage)
    });

    await tx1.sign();
    await tx1.send();

    block = await appChain.produceBlock();

    message = await appChain.query.runtime.MessageBox.agents.get(agentId);

    expect(block?.transactions[0].status.toBoolean()).toBe(false);
  }, 1_000_000);

  it("should fail with invalid message number", async () => {
    const agentId: AgentId = agentWL.keys().next().value;

    const newMessage: Message = {
      details: {
        agentId,
        text: MessageText.fromString("Hello World!"),
        securityCode: AgentCode.fromString("A7")
      },
      messageNumber: new MessageNumber(0)
    };

    let block = await appChain.produceBlock();
    let message = await appChain.query.runtime.MessageBox.agents.get(agentId);

    // agent does not exist in the state
    expect(message?.lastMessageNumber.equals(new MessageNumber(0)).toBoolean()).toBe(undefined);

    const tx1 = await appChain.transaction(agentPubKey, () => {
      messageBox.processMessage(newMessage)
    });

    await tx1.sign();
    await tx1.send();

    block = await appChain.produceBlock();

    message = await appChain.query.runtime.MessageBox.agents.get(agentId);

    expect(block?.transactions[0].status.toBoolean()).toBe(false);
  }, 1_000_000);

});
