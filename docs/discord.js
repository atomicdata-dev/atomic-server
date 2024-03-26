// https://docs.widgetbot.io/embed/crate/

var script = document.createElement('script');
script.src = 'https://cdn.jsdelivr.net/npm/@widgetbot/crate@3';
script.async = true;
script.defer = true;

document.body.appendChild(script);

script.onload = function () {
  new Crate({
    server: '723588174747533393',
    channel: '723588175351513152',
  });
};
