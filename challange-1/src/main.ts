import {
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  MerkleTree,
  MerkleMap,
  Poseidon,
  UInt32,
  MerkleWitness,
  UInt64,
} from 'o1js';

import { SecretMessage } from './SecretMessage.js';

const num_voters = 2; // Total Number of Voters
const options = 2; // TOtal Number of Options

class VoterListMerkleWitness extends MerkleWitness(num_voters + 1) {}
class VoteCountMerkleWitness extends MerkleWitness(options + 1) {}

let privateKeys: PrivateKey[] = [
  PrivateKey.random(),
  PrivateKey.random(),
  PrivateKey.random(),
  PrivateKey.random(),
];
let publicKeys: PublicKey[] = privateKeys.map((key) => key.toPublicKey());

class OffChainStorage {
  eligibleMerkleMap: MerkleMap;
  messageMerkleMap: MerkleMap;
  constructor() {
    this.eligibleMerkleMap = new MerkleMap();
    this.messageMerkleMap = new MerkleMap();
  }
  updateOffChainEligibleAddressState(eligibleAddressHash: Field) {
    this.eligibleMerkleMap.set(eligibleAddressHash, Field(1));
  }
  updateOffChainMessageState(message: Field, addressHash: Field) {
    this.messageMerkleMap.set(addressHash, message);
  }
}

let publicKeyHashes: Field[] = publicKeys.map((key) =>
  Poseidon.hash(key.toFields())
);

let offChainInstance = new OffChainStorage();

// ZkApp deployment

const useProof = false;

const Local = Mina.LocalBlockchain({ proofsEnabled: useProof });
Mina.setActiveInstance(Local);

const { privateKey: deployerKey, publicKey: deployerAccount } =
  Local.testAccounts[0];

// const { privateKey: user1PrivateKey, publicKey: user1PublicKey } =
//   Local.testAccounts[1];

// Create a public/private key pair. The public key is our address and where we will deploy to
const zkAppPrivateKey = PrivateKey.random();
const zkAppAddress = zkAppPrivateKey.toPublicKey();

// create an instance of Votes - and deploy it to zkAppAddress
const zkAppInstance = new SecretMessage(zkAppAddress);
const deployTxn = await Mina.transaction(deployerAccount, () => {
  AccountUpdate.fundNewAccount(deployerAccount);
  zkAppInstance.deploy();
});
console.log('zkApp deployed');
await deployTxn.sign([deployerKey, zkAppPrivateKey]).send();

// Deployer hash
const deployerHash = Poseidon.hash(deployerAccount.toFields());
console.log('deployerHash:', deployerHash.toString());

// Get owner
const owner = await zkAppInstance.owner.get();
console.log('owner:', owner.toBase58());

// Get initial message
const message = await zkAppInstance.message.get();
console.log('message:', message.toString());

// Get the root of eligible address merkle tree
let eligibleAddressMerkleRoot =
  await zkAppInstance.eligibleAddressMerkleRoot.get();
console.log('eligibleAddressMerkleRoot:', eligibleAddressMerkleRoot.toString());

const messageMerkleRoot = await zkAppInstance.messageMerkleRoot.get();
console.log('messageMerkleRoot:', messageMerkleRoot.toString());

{
  // Do voting and update the state of root of vote count merkle tree from user 1
  try {
    const user1PublicKeyHash = Poseidon.hash(deployerAccount.toFields());
    const MerkleMapWitnessUser1 =
      offChainInstance.eligibleMerkleMap.getWitness(user1PublicKeyHash);

    const [calculatedRoot, calculatedKey] =
      MerkleMapWitnessUser1.computeRootAndKey(Field(0));
    console.log('calculatedRoot:', calculatedRoot.toString());
    console.log('calculatedKey:', calculatedKey.toString());
    const txn = await Mina.transaction(deployerAccount, () => {
      zkAppInstance.addAddress(deployerAccount, MerkleMapWitnessUser1);
    });

    await txn.prove();
    const txnResult = await txn.sign([deployerKey]).send();
    // Update the offchain state
    if (txnResult.isSuccess) {
      const eligibleAddressHash = Poseidon.hash(deployerAccount.toFields());
      offChainInstance.updateOffChainEligibleAddressState(eligibleAddressHash);
      console.log('Eligible address updated');
    }
  } catch (err: any) {
    console.error('Error:', err.message);
  }
}

// Get the root of eligible address merkle tree
eligibleAddressMerkleRoot = await zkAppInstance.eligibleAddressMerkleRoot.get();
console.log('eligibleAddressMerkleRoot:', eligibleAddressMerkleRoot.toString());

{
  // Do voting and update the state of root of vote count merkle tree from user 1
  try {
    const user1PublicKeyHash = Poseidon.hash(deployerAccount.toFields());
    const MerkleMapWitnessUser1 =
      offChainInstance.eligibleMerkleMap.getWitness(user1PublicKeyHash);
    const [calculatedRoot, calculatedKey] =
      MerkleMapWitnessUser1.computeRootAndKey(Field(1));
    console.log('calculatedRoot:', calculatedRoot.toString());
    console.log('calculatedKey:', calculatedKey.toString());
    console.log('hash:', user1PublicKeyHash.toString());

    const MessageMerkleMapWitnessUser1 =
      offChainInstance.messageMerkleMap.getWitness(user1PublicKeyHash);
    const txn = await Mina.transaction(deployerAccount, () => {
      // AccountUpdate.fundNewAccount(user1PublicKey);
      zkAppInstance.depositMessage(
        Field(64),
        MerkleMapWitnessUser1,
        MessageMerkleMapWitnessUser1
      );
    });

    await txn.prove();
    const txnResult = await txn.sign([deployerKey]).send();
    // Update the offchain state
    if (txnResult.isSuccess) {
      console.log('Message deposited');
    }
  } catch (err: any) {
    console.error('Error:', err.message);
  }
}
