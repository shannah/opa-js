#!/usr/bin/env node
/**
 * Fetches the Hacker News RSS feed, packages it with a pirate-themed
 * summarization prompt, and writes a signed OPA file.
 *
 * Usage: node examples/hn-pirate.js
 * Output: hn-pirate-summary.opa in the current directory
 */
import { writeFile } from 'node:fs/promises';
import { OpaArchive, generateSigningKey } from '../src/index.js';

const FEED_URL = 'https://hnrss.org/newest?count=20';
const OUTPUT = 'hn-pirate-summary.opa';

function parseRSS(xmlText) {
  const itemRegex = /<item[\s>]([\s\S]*?)<\/item>/gi;
  const tag = (xml, name) => {
    const m = xml.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)<\\/${name}>`, 'i'));
    return m ? m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').trim() : '';
  };

  const feedTitle = tag(xmlText, 'title') || 'Hacker News';
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
  console.log(`Fetching ${FEED_URL} …`);
  const res = await fetch(FEED_URL);
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
    'Please write your entire response in the voice of a swashbuckling pirate:',
    '',
    '1. Write a concise summary (3-5 sentences) of the major themes and topics across all articles, using colorful pirate language.',
    '2. Highlight **one article** that ye think would be most interesting to a scallywag who follows AI and machine learning developments. Explain why ye chose it.',
    '3. List the top 5 articles by relevance to AI, with a one-sentence pirate summary of each.',
    '',
    'Output the report as HTML.',
    '',
    'Base your analysis only on the feed content provided in `data/feed.txt`.',
  ].join('\n');

  console.log('Generating signing key …');
  const { privateKey, publicKey } = await generateSigningKey();

  const archive = new OpaArchive({
    title: `Pirate Summary: ${feedTitle}`,
    description: `Summarize ${items.length} Hacker News articles in pirate voice with AI focus`,
    executionMode: 'batch',
    createdBy: 'opa-js/examples/hn-pirate',
  });

  archive.setPrompt(prompt);
  archive.addDataFile('feed.txt', feedText);
  archive.addDataFile('feed-raw.xml', xml);

  console.log('Building and signing archive …');
  const buf = await archive.toSignedUint8Array(privateKey, publicKey);
  await writeFile(OUTPUT, buf);
  console.log(`Wrote ${OUTPUT} (${(buf.length / 1024).toFixed(1)} KB)`);
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}
