```

crawlergo 使用了Chrome DevTools Protocol（CDP），通过与Chrome或Chromium浏览器进行通信，以便在爬取过程中模拟用户交互，捕获动态加载的内容和页面元素。

在 crawlergo 中，触发事件和监听事件的过程大致如下：

触发事件：crawlergo 通过 JavaScript 代码模拟触发页面中定义的各种事件。例如，在页面加载完成后，它会遍历页面中的所有元素，检查这些元素是否包含内联事件处理器（如 onclick、onmouseover 等），
并尝试触发这些事件。这有助于 crawlergo 发现可能因用户交互而显示的隐藏内容，以便在爬取过程中捕获这些内容。

监听事件：crawlergo 通过 CDP 监听浏览器中发生的各种事件。例如，当一个新的资源（如 AJAX 请求、图片、脚本等）被加载时，
crawlergo 会监听 Network.responseReceived 事件以获取资源的详细信息。此外，crawlergo 还可以监听诸如 DOMContentLoaded、load 等页面生命周期事件，以确保在适当的时机进行页面解析和内容提取。

自定义事件：crawlergo 还可以向页面中注入自定义 JavaScript 代码以实现特定功能。例如，可以在页面中注入一个名为 addLink 的函数，该函数可将传入的链接添加到页面中。
通过 CDP 中的 Runtime.addBinding 方法，crawlergo 可以在浏览器端与该函数进行双向通信。当页面中的 addLink 函数被调用时，
crawlergo 会收到一个 runtime.bindingCalled 事件通知，使其能够获取传入的链接并处理它们。

通过触发事件、监听事件以及与自定义 JavaScript 函数通信，crawlergo 能够模拟用户交互，捕获动态加载的内容，并提取页面中的链接和其他有价值的信息。这使得 crawlergo 成为一款非常强大和灵活的爬虫工具。

```