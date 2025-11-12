# JavaScript Files Code Guide
## Complete Reference for EdShed Game Chunk Files

---

## 📋 FILE OVERVIEW

### 2283.9266caa2.js
**Purpose:** Tower Defense Game Core Module
**Size:** ~14.7k lines
**Contains:**
- **Module 7411:** Beehive, Picnic, Temple map definitions
- **Module 15024-97080:** Set polyfills and utilities (Set.symmetricDifference, Set.union, etc.)
- **Module 62029:** Beehive map configuration
- **Module 70560:** Main game component and UI rendering (LARGEST MODULE - 13,700+ lines)

**What it does:**
- Exports map configurations for 3 tower defense levels
- Implements ES6 Set methods for compatibility
- Contains the main Phaser game scene and all game logic
- Manages units, enemies, towers, physics, scoring

**Key exports:**
- Maps: `beehive`, `picnic`, `temple`
- Game Scene class with physics simulation
- UI components for towers, enemies, health/money display

---

### 8831.3de7416d.js
**Purpose:** Challenges and Multiplayer Modal Component
**Size:** ~30 lines (highly minified)
**Contains:**
- **Module 14102:** ChallengesModal Vue component
- Multiple sub-modules: Avatar, RespondInvitationModal, ChallengeDetailsModal, CreateChallengeModal

**What it does:**
- Displays challenges/competitions to players
- Shows avatar components
- Handles challenge creation and responses
- Minimal actual code after minification

**Key exports:**
- `ChallengesModal` - Main modal component

---

### 7465.141997aa.js
**Purpose:** Game scene initialization and level selection
**Size:** ~14.8k lines
**Contains:**
- **Module 7411:** Map definitions (shared with 2283)
- **Module 46458:** Main scene/level selector component (LARGEST)
- Set polyfills and utilities

**What it does:**
- Initializes game scenes for different maps
- Handles level selection and transitions
- Manages game initialization

---

### 8783.b1ae1c24.js
**Purpose:** Keyboard and Phonics Data
**Size:** ~4.2k lines
**Contains:**
- **Module 20364:** Keyboard view component with mixin behavior
- **Module 23074:** Phonetic alphabet data, GPC mappings, and keyboard layouts

**What it does:**
- Defines keyboard layouts (QWERTY, Phonics modes)
- Maps letter phonemes and graphemes
- Handles keyboard input rendering for spelling games
- Exports phonetic data for different locales (en_GB, etc.)

**Key exports:**
- Keyboard component with phonics support
- Phoneme mappings (oz, c2, T8, ZV, Mf, ko, Gd)

---

### 764.aa236225.js
**Purpose:** Modal and Settings UI Components
**Size:** ~2k lines
**Contains:**
- **Module 70913:** BaseModal component (reusable modal dialog)
- **Module 73040:** Star rating library (minified markdown/rating code)
- **Module 86567:** SettingsModal component (pause menu, audio settings)
- **Module 93523:** Other UI utility classes

**What it does:**
- Provides reusable modal popup dialogs
- Implements settings/preferences UI
- Star rating widget for reviews
- Modal styling with Bulma CSS framework

**Key exports:**
- Modal component with customizable size, title, close warning
- SettingsModal for game settings
- Rating component

---

### app.c489ce2e.js
**Purpose:** Main Application Bundle
**Size:** ~11.3k lines
**Contains:**
- **Module 191:** Core exports and utilities (14 major functions)
- **Module 7504:** Settings/preferences data
- **Module 13693:** Settings mixin
- **Module 13865:** Keyboard/letter name data
- **Module 37626:** API calls and state management
- **Module 43564:** Large component library (5,100+ lines)
- Many more utility modules (47668, 53235, etc.)

**What it does:**
- Main Vue.js application entry point
- API communication with backend
- User authentication and state
- Settings and preferences management
- Large component library for UI

**Key exports:**
- Core app utilities
- API helpers
- State management
- UI component mixins

---

### 3777.7e795376.js
**Purpose:** Keyboard Input and Settings UI
**Size:** ~811 lines
**Contains:**
- **Module 21843:** KeyboardView component - displays interactive keyboard
- **Module 86567:** SettingsModal component (same as 764)

**What it does:**
- Renders on-screen keyboard for typing practice
- Handles keyboard events (click, hover, shift, backspace)
- Supports QWERTY and Phonics modes
- Phoneme pronunciation on hover

**Key exports:**
- KeyboardView component for spelling games
- SettingsModal for game settings

---

## 🔧 COMMON PATTERNS

### Module Structure
```javascript
ModuleID: function(exports, module, require) {
  "use strict";
  // require() imports other modules by ID
  // exports/module.exports = send data out
}
```

### Vue Components Pattern
```javascript
// Render function (n = render function)
var n = function() { /* returns JSX-like vnode */ }
// Component class or object
var ComponentClass = { /* props, methods, computed */ }
// Export decorated component
var exported = ComponentFactory(ComponentClass, renderFn, ...)
```

### Set Polyfills (ES6 compatibility)
- symmetricDifference, union, difference, intersection
- isSupersetOf, isSubsetOf, isDisjointFrom
- These add modern Set methods to older browsers

---

## 📊 DATA FLOW

```
User loads app
     ↓
app.c489ce2e.js (main app init)
     ↓
User selects game level
     ↓
7465 or 2283 (scene init)
     ↓
Phaser game starts (2283 module 70560)
     ↓
Game Loop:
  - Render game (Phaser)
  - Handle input (keyboard/mouse)
  - Update units/enemies/physics
  - Check collisions
  - Emit events
     ↓
User types spelling words
     ↓
3777 (KeyboardView) or 8783 (Keyboard+Phonics)
     ↓
Settings/pause menu
     ↓
764 (SettingsModal) or 86567
```

---

## 🎮 GAME MECHANICS (from 2283)

### Three Playable Maps
1. **Beehive** - Defend hive from attackers
   - 2 guard positions: (16.3, 3.5), (18.8, 4)
   - 1 main path for enemies
   
2. **Picnic** - Protect picnic basket from ants
   - 2 guard positions: (5.15, 3.8), (7.7, 3.8)
   - 2 paths: empty path + ant path
   
3. **Ruins (Temple)** - Two-route defense
   - 2 guard positions: (13.3, 3.8), (10.6, 3.8)
   - 2 separate enemy paths

### Game Objects
- **Units:** Defensive towers (bees, etc.)
- **Enemies:** Moving along paths
- **Projectiles:** From units attacking enemies
- **Health/Mana:** Gate health + currency (nectar/pollen)

### Modifiers/Powerups
- attack_spd_up: Increase tower attack speed
- attack_dmg_up: Increase tower damage
- enemy_spd_down: Slow enemies
- bug_zapper: Gate damages attackers
- spike_trap: Path trap for all enemies
- goggles: See small enemies
- iron_stinger: Damage shielded enemies

---

## 🎯 KEY FUNCTIONS & CLASSES

### From 2283 (Game Module)
- `Phaser.Physics.Arcade.Sprite` → Enemy/Unit base class
- `b.O` (extends Scene) → Main game scene
- `z(e)` → Conversion functions
- `R(e, i, n)` → Vector operations
- `M(e, i)` → Path calculations
- Various enemy/tower types: `j`, `q`, `T`, `re`, `Ce`

### From 3777/8783 (Keyboard)
- `KeyboardView` - Vue component for keyboard rendering
- `didKeyDown()` - Handle key presses
- `didClick()` - Handle mouse clicks
- `setKeyboard()` - Update keyboard layout
- `resizeKeyboard()` - Responsive sizing

### From 764 (Modals)
- `Modal` component - Generic modal wrapper
- `SettingsModal` - Game settings UI
- `closeModal()` - Handle closing with confirmation
- Properties: `open`, `title`, `large`, `closeWarning`

---

## 📝 IMPORTANT NOTES

1. **Minification:** Most code is heavily minified. Variable names like `t`, `e`, `i`, `n` are placeholder short names.

2. **Webpack Chunks:** Files are split chunks for lazy loading. They register with `self["webpackChunkgame"]`.

3. **Vue.js:** Components use Vue 2 with decorators (@Component, @Prop, @Watch).

4. **Phaser:** Game engine is Phaser (likely v3), used for physics, sprites, animations.

5. **Performance:** Large modules (14k+ lines) are broken up but still kept in single chunks for loading efficiency.

---

## 🔗 CROSS-FILE DEPENDENCIES

```
2283 (main game)
  ← 8783 (keyboard data)
  ← 3777 (keyboard UI)
  ← 764 (modals/settings)
  
7465 (scene init)
  ← 2283 (uses same maps)
  
app.c489ce2e.js (main app)
  → controls loading of all chunks
  → handles state/API for all chunks
```

---

**Last Updated:** November 12, 2025
