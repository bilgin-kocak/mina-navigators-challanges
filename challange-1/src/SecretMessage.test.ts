import { SecretMessage } from './SecretMessage';
import {
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  Bool,
  MerkleMap,
  MerkleMapWitness,
  Poseidon,
  Gadgets,
  UInt32,
} from 'o1js';

let proofsEnabled = false;

describe('SecretMessage', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    // this will be the account of the admin - person who can access contract
    adminAccount: PublicKey,
    adminKey: PrivateKey,
    // this will be a separate account that should not be able to access contract
    outsiderAccount: PublicKey,
    outsiderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: SecretMessage;

  beforeAll(async () => {
    if (proofsEnabled) await SecretMessage.compile();
  });

  beforeEach(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    ({ privateKey: adminKey, publicKey: adminAccount } = Local.testAccounts[1]);
    ({ privateKey: outsiderKey, publicKey: outsiderAccount } =
      Local.testAccounts[2]);
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new SecretMessage(zkAppAddress);
  });

  async function localDeploy() {
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy();
    });
    await txn.prove();
    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('correctly builds flags', async () => {
    // Both of these should result in flags which are ALL TRUE
    const messageAllTrue1 = Field(1 + 2 + 4 + 8 + 16 + 32);
    const messageAllTrue2 = Field(1 + 2 + 4 + 8 + 16 + 32 + 64 + 128);

    // Both of these should result in flags which are ALL FALSE
    const messageAllFalse1 = Field(64);
    const messageAllFalse2 = Field(64 + 128);

    const messageSomeTrue = Field(1 + 2 + 16 + 32 + 64 + 128);

    let [flag1, flag2, flag3, flag4, flag5, flag6] =
      zkApp.getFlags(messageAllTrue1);
    for (let flag of [flag1, flag2, flag3, flag4, flag5, flag6]) {
      expect(flag.toBoolean()).toBeTruthy();
    }
    [flag1, flag2, flag3, flag4, flag5, flag6] =
      zkApp.getFlags(messageAllTrue2);
    for (let flag of [flag1, flag2, flag3, flag4, flag5, flag6]) {
      expect(flag.toBoolean()).toBeTruthy();
    }

    [flag1, flag2, flag3, flag4, flag5, flag6] =
      zkApp.getFlags(messageAllFalse1);
    for (let flag of [flag1, flag2, flag3, flag4, flag5, flag6]) {
      expect(flag.toBoolean()).toBeFalsy();
    }

    [flag1, flag2, flag3, flag4, flag5, flag6] =
      zkApp.getFlags(messageAllFalse2);
    for (let flag of [flag1, flag2, flag3, flag4, flag5, flag6]) {
      expect(flag.toBoolean()).toBeFalsy();
    }

    [flag1, flag2, flag3, flag4, flag5, flag6] =
      zkApp.getFlags(messageAllFalse1);
    for (let flag of [flag1, flag2, flag3, flag4, flag5, flag6]) {
      expect(flag.toBoolean()).toBeFalsy();
    }

    [flag1, flag2, flag3, flag4, flag5, flag6] =
      zkApp.getFlags(messageSomeTrue);
    // From (1 + 2 + 16 + 32 + 64 + 128)
    // Flags 1, 2, 5, 6 should be true
    for (let flag of [flag1, flag2, flag5, flag6]) {
      expect(flag.toBoolean()).toBeTruthy();
    }
    for (let flag of [flag3, flag4]) {
      expect(flag.toBoolean()).toBeFalsy();
    }
  });

  it('addAddress() stores new addresses', async () => {
    await localDeploy();

    const address = PrivateKey.random().toPublicKey();

    const addressHash = Poseidon.hash(address.toFields());

    const eligibleMerkleMap = new MerkleMap();
    const eligibleMerkleMapWitness: MerkleMapWitness =
      eligibleMerkleMap.getWitness(addressHash);
    eligibleMerkleMap.set(addressHash, Field(1));

    const txnA = await Mina.transaction(deployerAccount, () => {
      zkApp.addAddress(address, eligibleMerkleMapWitness);
    });
    await txnA.prove();
    await txnA.sign([deployerKey]).send();

    const numAddresses = Number(zkApp.numAddresses.get().toBigInt()) as number;
    // Roots should match and we should have stored one address
    expect(numAddresses).toEqual(1);
    expect(zkApp.eligibleAddressMerkleRoot.get()).toEqual(
      eligibleMerkleMap.getRoot()
    );

    // And confirm if we try to store the same address again, it fails
    let failed = false;
    try {
      const txnB = await Mina.transaction(deployerAccount, () => {
        zkApp.addAddress(address, eligibleMerkleMapWitness);
      });
      await txnB.prove();
      await txnB.sign([deployerKey]).send();
    } catch (e: any) {
      failed = true;
    }
    expect(failed).toBeTruthy();
  });

  it.only('deposites new messages', async () => {
    await localDeploy();

    // Need to add it to the map first
    const address = PrivateKey.random().toPublicKey();
    const addressHash = Poseidon.hash(address.toFields());
    const eligibleMerkleMap = new MerkleMap();
    let eligibleMerkleMapWitness: MerkleMapWitness =
      eligibleMerkleMap.getWitness(addressHash);
    let merkleRoot = zkApp.eligibleAddressMerkleRoot.get();
    console.log('merkleRoot:', merkleRoot.toString());
    eligibleMerkleMap.set(addressHash, Field(1));
    const txnA = await Mina.transaction(deployerAccount, () => {
      zkApp.addAddress(address, eligibleMerkleMapWitness);
    });
    await txnA.prove();
    await txnA.sign([deployerKey]).send();

    const message = Field(64);
    eligibleMerkleMapWitness = eligibleMerkleMap.getWitness(addressHash);

    const messageMerkleMap = new MerkleMap();
    const messageMerkleWitness = messageMerkleMap.getWitness(addressHash);

    const numMessages = Number(zkApp.numDepositedMessages.get().toBigInt());
    console.log('numMessages:', numMessages);

    merkleRoot = zkApp.eligibleAddressMerkleRoot.get();
    console.log('merkleRoot:', merkleRoot.toString());

    // const txnB = await Mina.transaction(deployerAccount, () => {
    //   zkApp.depositMessage(
    //     message,
    //     eligibleMerkleMapWitness,
    //     messageMerkleWitness
    //   );
    // });
    // await txnB.prove();
    // await txnB.sign([deployerKey]).send();

    // messageMerkleMap.set(addressHash, message);

    // // Make sure we've now received 1 message and roots match
    // let numDepositedMessages = Number(
    //   zkApp.numDepositedMessages.get().toBigInt()
    // ) as number;
    // expect(numDepositedMessages).toEqual(1);
    // expect(zkApp.eligibleAddressMerkleRoot.get()).toEqual(
    //   eligibleMerkleMap.getRoot()
    // );
  });
});
