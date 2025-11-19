import {
  CompactTypeBytes,
  CompactTypeEnum,
  CompactTypeUnsignedInteger
} from '@midnight-ntwrk/compact-runtime';

const _bytes32 = new CompactTypeBytes(32);
const _enum = new CompactTypeEnum(2, 1);
const _uint = new CompactTypeUnsignedInteger(2n, 1);

console.log('=== ENUM Alignment ===');
console.log('Enum alignment:', _enum.alignment());
console.log('Enum toValue(0):', _enum.toValue(0));
console.log('Enum toValue(1):', _enum.toValue(1));
console.log('Enum toValue(2):', _enum.toValue(2));

console.log('\n=== UINT Alignment ===');
console.log('Uint alignment:', _uint.alignment());
console.log('Uint toValue(0):', _uint.toValue(0n));
console.log('Uint toValue(1):', _uint.toValue(1n));
console.log('Uint toValue(2):', _uint.toValue(2n));

console.log('\n=== Descriptor with ENUM ===');
class EnumDescriptor {
  alignment() {
    return _bytes32.alignment()
      .concat(_enum.alignment())
      .concat(_bytes32.alignment());
  }
  toValue(obj: any): Uint8Array[] {
    return (_bytes32.toValue(obj.a) as Uint8Array[])
      .concat(_enum.toValue(obj.b) as Uint8Array[])
      .concat(_bytes32.toValue(obj.c) as Uint8Array[]);
  }
}

console.log('\n=== Descriptor with UINT ===');
class UintDescriptor {
  alignment() {
    return _bytes32.alignment()
      .concat(_uint.alignment())
      .concat(_bytes32.alignment());
  }
  toValue(obj: any): Uint8Array[] {
    return (_bytes32.toValue(obj.a) as Uint8Array[])
      .concat(_uint.toValue(obj.b) as Uint8Array[])
      .concat(_bytes32.toValue(obj.c) as Uint8Array[]);
  }
}

const testObj = {
  a: new Uint8Array(32).fill(1),
  b: 0,
  c: new Uint8Array(32).fill(3)
};

const enumDesc = new EnumDescriptor();
const uintDesc = new UintDescriptor();

console.log('\nEnum descriptor alignment length:', enumDesc.alignment().length);
console.log('Uint descriptor alignment length:', uintDesc.alignment().length);

const enumValues = enumDesc.toValue(testObj);
const uintValues = uintDesc.toValue(testObj);

console.log('\nEnum toValue returns', enumValues.length, 'arrays');
console.log('Uint toValue returns', uintValues.length, 'arrays');

console.log('\nEnum array lengths:', enumValues.map(a => a.length));
console.log('Uint array lengths:', uintValues.map(a => a.length));

// Calculate total bytes
const enumTotalBytes = enumValues.reduce((sum, arr) => sum + arr.length, 0);
const uintTotalBytes = uintValues.reduce((sum, arr) => sum + arr.length, 0);

console.log('\nEnum total bytes:', enumTotalBytes);
console.log('Uint total bytes:', uintTotalBytes);
console.log('Difference:', enumTotalBytes - uintTotalBytes, 'bytes');
