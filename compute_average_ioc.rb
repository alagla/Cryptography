def compute_ioc(text, start, skip)
  frequencies = Hash.new{|h, k| h[k] = 0}
  (start..text.size-1).step(skip) do |i|
    frequencies[text[i]] += 1
  end
  ioc = 0
  frequencies.each_value do |frequency|
    ioc += frequency*(frequency-1)
  end
  ioc /= 1.0*(text.size/skip)*((text.size-1)/skip)
  return ioc
end

if ARGV.size != 2 then
  puts "Usage: compute_average_ioc.rb <possible keyword length> <text file name>"
  exit
end
keyword_length = ARGV.shift.to_i
filename = ARGV.shift
textfile = File.new(filename, "r")
text = textfile.read
if keyword_length < 1 then
  puts "The keyword length value must be greater than 0."
  exit
end
N = text.size
average_ioc = 0.0
(0..keyword_length-1).each do |i|
  ioc = compute_ioc(text, i, keyword_length)
  average_ioc += ioc
end
average_ioc /= 1.0*keyword_length
puts "The average IOC is %7.5f" % average_ioc
