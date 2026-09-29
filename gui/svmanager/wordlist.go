package svmanager

import (
	"slices"
	"strings"
	"sync"
)

// wordList is the words passphrases are drawn from: short, common English
// words, easy to type and to tell apart, with no repeats. It is secretvault's
// own list. How many there are sets how much each word is worth (log2 of
// the count, a little over 10 bits); the generator says so.
func wordList() []string {
	wordsOnce.Do(func() {
		seen := map[string]bool{}
		for _, w := range strings.Fields(wordText) {
			if !seen[w] {
				seen[w] = true
				words = append(words, w)
			}
		}
		slices.Sort(words)
	})
	return words
}

var (
	wordsOnce sync.Once
	words     []string
)

const wordText = `
able acid acorn actor adapt adult affix agent agile aglow aisle alarm album alert algae alien alley almond aloe
alpine amber ample anchor angle ankle annex anvil apple apron arbor arch arena argue armor army aroma arrow
artist ascend ash aspen asset atlas atom attic audio august aunt autumn avenue avocado award awning axis
bacon badge bagel baker balance ball bamboo banana band banjo barn barrel basil basin basket bath beach beacon
beam bean bear beaver bed beech beetle begin bell belt bench berry bicycle bingo birch bird biscuit bison
blade blanket blaze blend blink bloom blossom blue board boat bolt bonus book boot border bottle boulder bowl
brain branch brave bread breeze brick bridge brief bright broom brook brush bubble bucket buckle budget buffalo
bugle bulb bundle bunny burrow butter button cabin cable cactus cake calm camel camera camp canal candle
candy canoe canvas canyon cape captain caramel card cargo carpet carrot cart castle cat cedar cellar cello
cement chain chair chalk chapel charm chart cheese cherry chess chest chimney choir chord cider cinema circle
city clam clay cliff climb clock cloud clover coach coast cobalt cocoa coconut coffee coin comet compass
copper coral cork corn cosmos cotton couch country cousin crane crater crayon cream creek crisp crow crown
cube cup curtain cushion cycle daisy dance dawn deck deer delta denim desert desk dial diary dinner dish
dock dolphin domain donkey door dough dove dragon drama drawer dream dress drift drum duck dune dusk dust
eagle earth easel echo eclipse edge elbow elder elm ember emerald engine envoy epic equal essay ever exit
fable fabric falcon fancy farm feast feather fence fern ferry festival fever fiber field fig film finch
fire fish flag flame flask fleet flint flock flower flute foam focus fog folder forest forge fork fossil
fountain fox frame fresh frog frost fruit galaxy garden garlic gate gauge gear gem genius giant ginger giraffe
glacier glass globe glove glow goat gold golf goose gorilla grain grape graph grass gravel gravy green grid
grove guard guest guitar gulf habit hammer hammock harbor harp harvest hat hawk hazel heart hedge helmet
herb hero heron hill hinge hobby honey hood hook horizon horn horse hotel hound house humble hummus
iceberg icon idea igloo image index indigo ink inlet insect island ivory ivy jacket jaguar jam jar jasmine
jazz jelly jersey jewel jigsaw jockey journal journey joy judge juice jungle juniper kayak kernel kettle key
kidney kind king kite kitten kiwi knee knight knot koala label ladder ladle lagoon lake lamb lamp lantern
laptop latch lava lawn leaf ledge lemon lens leopard letter lever library lilac lily lime linen lion
liquid lizard llama lobster locket lodge lotus lucky lunar lunch lynx magnet mango manor maple marble margin
market marsh mask meadow medal melody melon memo menu meteor metro micro milk mill mineral mint mirror
mitten model monkey moon moose morning mosaic moss motor mountain mouse muffin mural museum music napkin
narrow nature nectar needle nest net nickel night noble noodle north novel nugget nutmeg oak oasis oat ocean
octave olive omega onion opal opera orange orbit orchard orchid organ otter outer oven owl oyster paddle
page paint palace palm panda panel paper parade parcel park parrot pasta pastel patio peach peanut pear
pearl pebble pecan pelican pencil pepper piano pickle picnic pier pigeon pillow pilot pine pioneer pipe
pirate pistachio pixel pizza plain planet plank plate plaza plum pocket poem polar pond pony popcorn poppy
porch portal potato pottery powder prairie prism pumpkin puppet puzzle pyramid quail quarry quartz queen quest
quiet quill quilt rabbit radar radio radish raft rain raisin ramp ranch raven razor recipe reef relay remote
reptile ribbon rice ridge ring ripple river road robin rocket rodeo roof room root rope rose ruby rudder
rug ruler saddle safari saffron sage sail salad salmon salt sand satin saucer savanna scale scarf school
scooter scout sea seal season seed shadow shark shelf shell shelter ship shore shovel shrimp signal silk
silver siren sketch ski sky slate sled slope snail snow soap sofa solar sonnet soup spark sparrow spice
spider spinach spoon spring spruce square squid stable stadium stamp star station statue steam steel stem
stone stool storm story stove straw stream street sugar suit summer summit sun sunset swan sweater swing
syrup table tablet taco tail talent tango tank tapestry target tea teapot temple tennis tent thistle thread
thunder ticket tide tiger timber tulip tunnel turkey turnip turtle tuxedo twig umbrella uncle unicorn union
unit urban utensil valley vanilla vase velvet verse vessel vest vial video village vine violet violin
visitor volcano voyage wagon waffle walnut walrus wand warm water wave wax weaver wedge whale wheat wheel
whistle willow window winter wire wisdom wizard wolf wonder wool world wren yacht yard yarn yeast yellow
yogurt yolk zebra zenith zero zinc zipper zone zoo
acre agenda airport ajar alcove alder alpaca amulet anthem antler apricot aqua arcade ardent aria armchair
autograph backpack badger ballad balloon banner barley baton battery bazaar beagle bedrock beehive bellow
beret biplane blimp blueprint bobcat bonfire bouquet bramble brass breadbox brisk bronze buckwheat bugle
bungalow cabbage caboose cadet caliper calm cameo canopy capsule cardinal carousel cashew catalog cathedral
cavern celery chamber chariot cheetah chestnut chipmunk chisel cinnamon citrus clarinet clipper cobble
cockpit collar condor cookie cornet cottage cougar cowboy coyote cradle cricket crocus crystal cupcake
curry cymbal dairy dandelion daybreak decoy denim diamond dinghy dingo dipper dogwood domino doodle
dormouse dragonfly drizzle dumpling dynamo easel eggplant elephant elevator elk embassy emblem encore
envelope estuary evergreen falafel fawn ferret fiddle fiesta firefly fjord flamingo flannel flipper foghorn
fondue footpath fresco fudge funnel gadget galleon gallop gazebo gecko geyser gingham glider goblet gondola
gopher granite gravity griddle grizzly gumdrop gypsum hamlet hamster hangar harmony hatchet haystack hazelnut
headland hedgehog helium hemlock heritage hickory highland hilltop hippo holly homestead hornet hummingbird
iguana inkwell iris jackal jalopy jetty jubilee kaleidoscope kangaroo keel kelp kestrel keystone kiln kingdom
kipper knapsack lacquer ladybug lamplight landmark lark lasso lattice laurel lavender lemonade lentil
lighthouse limestone linden locomotive loft lollipop lookout lullaby macaw magnolia mahogany mallard mammoth
mandolin mantis marigold marina marmalade marzipan mast meerkat merit mesa milestone minnow mistletoe moat
molasses monsoon moonbeam moth muffler mulberry mustang nautilus nebula nightingale nomad nutshell oatmeal
obelisk ocelot omelet opossum orca origami ostrich outpost overture paddock pagoda palette pampas pancake
panther papaya parasol parchment parsley partridge pavilion peacock peppermint periscope petal pewter
pheasant piccolo pinecone pinwheel platypus plover plume pollen pomegranate porcupine postcard
prawn pretzel primrose propeller pudding puffin quiche quokka raccoon railway rainbow rampart raspberry
redwood reindeer rhubarb riddle riverbank robot rosemary rowboat safflower sailboat sandal sapphire sardine
sawmill scallop scarecrow schooner scroll seahorse seashell sequoia sesame shamrock sherbet shipyard
skylark skyline slipper snapdragon snowflake songbird sorbet soybean spaniel spatula spinnaker sprocket
squirrel starfish steeple stingray strudel sunflower surfboard swallow sycamore tadpole tamarind tambourine
tangerine teacup telescope terrace thimble thrush thyme toboggan toffee tomato topaz tortoise toucan trellis
trolley trombone trumpet tugboat tundra turbine turquoise twilight typewriter ukulele upland vapor veranda
viaduct vineyard vulture walkway wallaby warbler waterfall weasel whisker wicker wigwam windmill wolverine
woodland woodpecker xylophone yodel yucca zeppelin zucchini
`
