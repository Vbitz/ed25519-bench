const worker = new Worker(new URL('./worker.ts', import.meta.url), {
  type: 'module',
});

const pre = document.querySelector('#pre');

if (pre === null) {
  throw new Error('Not Implemented');
}

worker.addEventListener('message', ev => {
  pre.insertBefore(document.createTextNode(ev.data + '\n'), pre.firstChild);
});
