import {
  Field,
  SmartContract,
  state,
  State,
  method,
  MerkleMap,
  MerkleTree,
  MerkleWitness,
  PublicKey,
  Poseidon,
  MerkleMapWitness,
  Bool,
  Gadgets,
  Circuit,
  Provable,
  UInt64,
} from 'o1js';

// 2^8 = 256 is bigger than the nummber of eligible addresses which is 100
class MyMerkleWitness extends MerkleWitness(8) {}

export class SecretMessage extends SmartContract {
  @state(PublicKey) owner = State<PublicKey>();
  @state(Field) eligibleAddressMerkleRoot = State<Field>();
  @state(Field) messageMerkleRoot = State<Field>();
  @state(Field) numDepositedMessages = State<UInt64>();
  @state(Field) message = State<Field>();
  @state(UInt64) numAddresses = State<UInt64>();
  events = {
    'message-deposited': UInt64,
  };

  init() {
    super.init();
    this.eligibleAddressMerkleRoot.set(new MerkleMap().getRoot());
    this.owner.set(this.sender);
    this.message.set(Field(0));
    this.numAddresses.set(UInt64.from(0));
    this.messageMerkleRoot.set(new MerkleMap().getRoot());
    this.numDepositedMessages.set(UInt64.from(0));
  }

  /**
   * @notice Throws if called by any account other than the owner.
   */
  @method
  onlyOwner() {
    const owner = this.owner.getAndRequireEquals();

    // check that the sender is the owner
    owner.assertEquals(this.sender);
  }

  // @method initState(eligibleAddressMerkleRoot: Field) {}

  @method addAddress(
    publicKey: PublicKey,
    eligibleAdressWitness: MerkleMapWitness
  ) {
    // Only owner can add address
    this.onlyOwner();

    const numAddresses = this.numAddresses.getAndRequireEquals();
    numAddresses.assertLessThan(UInt64.from(100)),
      'No more than 100 addresses can be added';

    const currentState = this.eligibleAddressMerkleRoot.getAndRequireEquals();

    // Get the hash of public key
    const hash = Poseidon.hash(publicKey.toFields());

    // Calculate the root of merkleMap
    const [calculatedRoot, calculatedKey] =
      eligibleAdressWitness.computeRootAndKey(Field(0));
    // Make sure that eligible address does not added before
    this.eligibleAddressMerkleRoot.requireEquals(calculatedRoot);
    calculatedKey.assertEquals(hash);

    // Update the root
    const [calculatedNewRoot, calculatedNewKey] =
      eligibleAdressWitness.computeRootAndKey(Field(1));
    calculatedNewKey.assertEquals(hash);

    // Update the states
    this.eligibleAddressMerkleRoot.set(calculatedNewRoot);
    this.numAddresses.set(numAddresses.add(1));
  }

  @method onlyEligibleAddress(eligibleAdressWitness: MerkleMapWitness) {
    const [calculatedRoot, calculatedKey] =
      eligibleAdressWitness.computeRootAndKey(Field(1));
    const hash = Poseidon.hash(this.sender.toFields());
    // Make sure that eligible address is calculatedKey
    hash.assertEquals(calculatedKey);
    // Make sure that eligible address is in the merkle tree
    this.eligibleAddressMerkleRoot.requireEquals(calculatedRoot);
  }

  @method depositMessage(
    message: Field,
    eligibleAdressWitness: MerkleMapWitness,
    messageMerkleWitness: MerkleMapWitness
  ) {
    // Only eligible address can deposit message
    this.onlyEligibleAddress(eligibleAdressWitness);
    const currentState = this.eligibleAddressMerkleRoot.getAndRequireEquals();
    const currentState2 = this.messageMerkleRoot.getAndRequireEquals();

    const numDepositedMessages =
      this.numDepositedMessages.getAndRequireEquals();

    // Check the message has correct flags
    this.checkFlags(message);

    // Get the hash of public key
    const hash = Poseidon.hash(this.sender.toFields());

    // Calculate the root of message merkleMap
    const [calculatedRoot, calculatedKey] =
      messageMerkleWitness.computeRootAndKey(Field(0));
    // Make sure that eligible address does not deposited message before
    // If the address has deposited message before, the root will be different therefore the requireEquals will fail
    this.messageMerkleRoot.requireEquals(calculatedRoot);
    calculatedKey.assertEquals(hash);

    // Update the root
    const [calculatedNewRoot, calculatedNewKey] =
      messageMerkleWitness.computeRootAndKey(message);
    calculatedNewKey.assertEquals(hash);

    // Update the states
    this.messageMerkleRoot.set(calculatedNewRoot);

    // Update the number of deposited messages
    this.numDepositedMessages.set(numDepositedMessages.add(1));

    // this.emitEvent('message-deposited', numDepositedMessages.add(1));
    // this.message.set(message);
  }

  getFlags(message: Field): [Bool, Bool, Bool, Bool, Bool, Bool] {
    // message must be longer than 32 bits so that we can extract the flags
    message.assertGreaterThan(Field(32));

    const bit6 = Field(1); // ... 000001 = 1
    const bit5 = Field(2); // ... 000010 = 2
    const bit4 = Field(4); // ... 000100 = 4
    const bit3 = Field(8); // ... 001000 = 8
    const bit2 = Field(16); // ... 010000 = 16
    const bit1 = Field(32); // ... 100000 = 32

    // have to specify 64 bits or it tries to do 16 bits?
    const g6 = Gadgets.and(message, bit6, 64); // ... 000001
    const g5 = Gadgets.and(message, bit5, 64); // ... 000010
    const g4 = Gadgets.and(message, bit4, 64); // ... 000100
    const g3 = Gadgets.and(message, bit3, 64); // ... 001000
    const g2 = Gadgets.and(message, bit2, 64); // ... 010000
    const g1 = Gadgets.and(message, bit1, 64); // ... 100000

    const flag6: Bool = g6.equals(bit6);
    const flag5: Bool = g5.equals(bit5);
    const flag4: Bool = g4.equals(bit4);
    const flag3: Bool = g3.equals(bit3);
    const flag2: Bool = g2.equals(bit2);
    const flag1: Bool = g1.equals(bit1);

    return [flag1, flag2, flag3, flag4, flag5, flag6];
  }

  checkFlags(message: Field) {
    const [flag1, flag2, flag3, flag4, flag5, flag6] = this.getFlags(message);

    // If flag 1 is true, then all other flags must be false
    const condition1: Bool = Provable.if(
      flag1.equals(Bool(true)),
      flag2
        .equals(false)
        .and(flag3.equals(false))
        .and(flag4.equals(false))
        .and(flag5.equals(false))
        .and(flag6.equals(false)),
      Bool(true)
    );

    // If flag 2 is true, then flag 3 must also be true.
    const condition2: Bool = Provable.if(
      flag1.equals(Bool(true)),
      flag3.equals(true),
      Bool(true)
    );

    // If flag 4 is true, then flags 5 and 6 must be false.
    const condition3: Bool = Provable.if(
      flag4.equals(true),
      flag5.equals(false).and(flag6.equals(false)),
      Bool(true)
    );

    // All conditions must be true
    condition1.assertEquals(Bool(true));
    condition2.assertEquals(Bool(true));
    condition3.assertEquals(Bool(true));
  }
}
