// https://docs.widgetbot.io/embed/crate/

var script = document.createElement('script');
script.src = 'https://cdn.jsdelivr.net/npm/@widgetbot/crate@3';
script.async = true;
script.defer = true;

document.body.appendChild(script);

script.onload = function () {
  new Crate({
    server: '299881420891881473',
    channel: '355719584830980096',
  });
};
