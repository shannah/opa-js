#!/usr/bin/env node
/**
 * CLI version of the RSS summarizer example.
 *
 * Usage:
 *   node examples/cli-rss.js [feed-url] [-o output.opa]
 *
 * Defaults:
 *   feed-url  https://hnrss.org/newest?count=20
 *   output    <feed-title>.opa in the current directory
 */
import { writeFile } from 'node:fs/promises';
import { OpaArchive } from '../src/index.js';

const args = process.argv.slice(2);

let feedUrl = 'https://hnrss.org/newest?count=20';
let outputPath = null;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '-o' && args[i + 1]) {
    outputPath = args[++i];
  } else if (!args[i].startsWith('-')) {
    feedUrl = args[i];
  }
}

function parseRSS(xmlText) {
  // Minimal XML extraction without a DOM parser
  const itemRegex = /<item[\s>]([\s\S]*?)<\/item>/gi;
  const tag = (xml, name) => {
    const m = xml.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)<\\/${name}>`, 'i'));
    return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim() : '';
  };

  const feedTitle = tag(xmlText, 'title') || 'Unknown Feed';

  const items = [];
  let m;
  while ((m = itemRegex.exec(xmlText)) !== null) {
    items.push({
      title: tag(m[1], 'title'),
      link: tag(m[1], 'link'),
      description: tag(m[1], 'description'),
      pubDate: tag(m[1], 'pubDate'),
    });
  }
  return { feedTitle, items };
}

try {
  console.log(`Fetching ${feedUrl} …`);
  const res = await fetch(feedUrl);
  if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
  const xml = await res.text();

  const { feedTitle, items } = parseRSS(xml);
  if (items.length === 0) throw new Error('No items found in feed.');
  console.log(`Parsed ${items.length} items from "${feedTitle}"`);

  const feedText = items
    .map(
      (it, i) =>
        `## ${i + 1}. ${it.title}\n` +
        `Link: ${it.link}\n` +
        `Date: ${it.pubDate}\n` +
        `${it.description}\n`
    )
    .join('\n---\n\n');

  const prompt = [
    `# Summarize RSS Feed: ${feedTitle}`,
    '',
    `You have been given an RSS feed snapshot in \`data/feed.txt\` containing ${items.length} articles from "${feedTitle}".`,
    '',
    'Please:',
    '',
    '1. Write a concise summary (3-5 sentences) of the major themes and topics across all articles.',
    '2. Highlight **one article** that you think would be most interesting to someone who follows AI and machine learning developments. Explain why you chose it.',
    '3. List the top 5 articles by relevance to AI, with a one-sentence summary of each.',
    '',
    'Output the report as HTML.',
    '',
    'Base your analysis only on the feed content provided in `data/feed.txt`.',
  ].join('\n');

  const archive = new OpaArchive({
    title: `RSS Summary: ${feedTitle}`,
    description: `Summarize ${items.length} articles from ${feedTitle} with AI focus`,
    executionMode: 'batch',
    createdBy: 'opa-js/examples/cli-rss',
  });

  archive.setPrompt(prompt);
  archive.addDataFile('feed.txt', feedText);
  archive.addDataFile('feed-raw.xml', xml);

  const filename =
    outputPath ||
    feedTitle
      .replace(/[^a-zA-Z0-9]+/g, '-')
      .toLowerCase()
      .slice(0, 40) + '.opa';

  const buf = archive.toUint8Array();
  await writeFile(filename, buf);
  console.log(`Wrote ${filename} (${(buf.length / 1024).toFixed(1)} KB)`);
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}
