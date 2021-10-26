import {createHash, randomBytes} from 'crypto';
import * as ed25519 from 'noble-ed25519';

const self = globalThis as unknown as Worker;

function time() {
  if (process.hrtime !== undefined) {
    return Number(process.hrtime.bigint());
  } else {
    return performance.now();
  }
}

class Ed25519Wrapper {
  static async hashData(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(createHash('SHA512').update(data).digest().buffer);
  }

  static async sign(
    dataHash: Uint8Array,
    privateKey: Uint8Array
  ): Promise<Uint8Array> {
    return await ed25519.sign(dataHash, privateKey);
  }

  static async verify(
    signature: Uint8Array,
    dataHash: Uint8Array,
    publicKey: Uint8Array
  ): Promise<boolean> {
    return await ed25519.verify(signature, dataHash, publicKey);
  }

  static async makePrivateKey(): Promise<Uint8Array> {
    return ed25519.utils.randomPrivateKey();
  }

  static async getPublicKey(privateKey: Uint8Array): Promise<Uint8Array> {
    return await ed25519.getPublicKey(privateKey);
  }
}

class DataGenerator {
  static async generateBytes(size: number): Promise<Uint8Array> {
    return new Uint8Array(randomBytes(size).buffer);
  }
}

async function timeBlock<T>(cb: () => Promise<T>): Promise<[T, number]> {
  const start = time();

  const ret = await cb();

  const end = time();

  return [ret, end - start];
}

function approxRollingAverage(avg: number, newSample: number, n: number) {
  avg -= avg / n;
  avg += newSample / n;

  return avg;
}

function numberWithCommas(x: string) {
  // From: https://stackoverflow.com/questions/2901102/how-to-print-a-number-with-commas-as-thousands-separators-in-javascript
  return x.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

async function main(args: string[]): Promise<number> {
  const privateKey = await Ed25519Wrapper.makePrivateKey();
  const publicKey = await Ed25519Wrapper.getPublicKey(privateKey);

  const looping = true;

  let generateDataAverage = 0;
  let hashDataAverage = 0;
  let signDataAverage = 0;
  let verifyAverage = 0;

  let totalSamples = 0;

  while (looping) {
    const [data, generateDataTime] = await timeBlock(
      async () => await DataGenerator.generateBytes(2048)
    );
    const [dataHash, hashDataTime] = await timeBlock(
      async () => await Ed25519Wrapper.hashData(data)
    );
    const [signature, signDataTime] = await timeBlock(
      async () => await Ed25519Wrapper.sign(dataHash, privateKey)
    );
    const [verifyResult, verifyTime] = await timeBlock(
      async () => await Ed25519Wrapper.verify(signature, dataHash, publicKey)
    );

    if (verifyResult === false) {
      console.error('Failed to Verify');
      break;
    }

    generateDataAverage = approxRollingAverage(
      generateDataAverage,
      Number(generateDataTime),
      100
    );
    hashDataAverage = approxRollingAverage(
      hashDataAverage,
      Number(hashDataTime),
      100
    );
    signDataAverage = approxRollingAverage(
      signDataAverage,
      Number(signDataTime),
      100
    );
    verifyAverage = approxRollingAverage(
      verifyAverage,
      Number(verifyTime),
      100
    );

    totalSamples += 1;

    if (totalSamples % 100 === 0) {
      self.postMessage(
        [
          'totalSamples',
          numberWithCommas(totalSamples.toString().padStart(10, '0')),
          'generate',
          numberWithCommas(generateDataAverage.toFixed(3)) + 'ms',
          'hash',
          numberWithCommas(hashDataAverage.toFixed(3)) + 'ms',
          'sign',
          numberWithCommas(signDataAverage.toFixed(3)) + 'ms',
          'verify',
          numberWithCommas(verifyAverage.toFixed(3)) + 'ms',
        ].join(' ')
      );
    }
  }

  return 0;
}

if (require.main === module) {
  main(process.argv.slice(2))
    .then(exitCode => (process.exitCode = exitCode))
    .catch(err => {
      console.error('Fatal', err);
      // eslint-disable-next-line no-process-exit
      process.exit(1);
    });
} else {
  main(process.argv.slice(2)).catch(err => {
    console.error('Fatal', err);
  });
}
