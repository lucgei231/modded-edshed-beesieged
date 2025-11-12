"use strict";
(
  self["webpackChunkgame"] = self["webpackChunkgame"] || []
).push([
  [6487],
  {
    7411: function (e, t, a) {
      a.d(t, {
        A: function () {
          return l;
        },
      });
      var s = a(62029),
        i = a(4440),
        n = a.n(i),
        o = {
          key: "picnic",
          name: "Picnic",
          description: "Protect your picnic basket! Those sneaky ants are taking a shortcut!",
          royalGuardAreas: [
            { x: 5.15, y: 3.8 },
            { x: 7.7, y: 3.8 },
          ],
          paths: [
            { key: "picnic_path", enemyTypes: [], path: new n().Curves.Path, pathLength: 0, pathPoints: [] },
            { key: "picnic_ants", enemyTypes: ["ant"], path: new n().Curves.Path, pathLength: 0, pathPoints: [] },
          ],
        },
        r = {
          key: "temple",
          name: "Ruins",
          description: "An ancient hive is under attack! Enemies will take two routes, so be careful!",
          royalGuardAreas: [
            { x: 13.3, y: 3.8 },
            { x: 10.6, y: 3.8 },
          ],
          paths: [
            { key: "temple_1", enemyTypes: [], path: new n().Curves.Path, pathLength: 0, pathPoints: [] },
            { key: "temple_2", enemyTypes: [], path: new n().Curves.Path, pathLength: 0, pathPoints: [] },
          ],
        },
        l = { beehive: s.A, picnic: o, temple: r };
    },

    62029: function (e, t, a) {
      var s = a(4440),
        i = a.n(s);
      t.A = {
        key: "beehive",
        name: "HACKED BEEHIVE",
        description: "Defend the hive from incoming attackers!",
        royalGuardAreas: [{ x: 16.3, y: 3.5 }, { x: 18.8, y: 4 }],
        paths: [{ key: "beehive_path", enemyTypes: [], path: new i().Curves.Path, pathLength: 0, pathPoints: [] }],
      };
    },

    66487: function (e, t, a) {
      a.r(t),
        a.d(t, {
          default: function () {
            return y;
          },
        });

      var s = function () {
          var e = this,
            t = e.$createElement,
            a = e._self._c || t;
          return e.initialised
            ? a(
                "div",
                {
                  staticClass: "tower-game-menu",
                  class: {
                    "begin-animation": "begin" === e.show,
                    "show-menu": e.showMainMenu,
                    "side-menu-open": e.sideMenuOpen,
                  },
                },
                [
                  a("div", { staticClass: "tower-game-menu__white" }),
                  a("div", {
                    staticClass: "tower-game-menu__background",
                    class: { "show-menu": e.showMainMenu },
                  }),
                  a("div", { staticClass: "tower-game-menu__inner" }, [
                    a("header"),
                    a("main", [e._m(0),
                      a(
                        "div",
                        {
                          staticClass: "tower-game-menu__main",
                          class: { active: e.showMainMenu },
                          on: { click: function (t) { e.sideMenuOpen = !1; } },
                        },
                        [
                          a("div", { staticClass: "tower-game-menu__main__inner" }, [
                            "map" === e.show
                              ? a("div", { staticClass: "tower-game-menu__maps" }, [
                                  a("h2", [e._v("Select a Map")]),
                                  e.needsToDoMiniDiagnostic
                                    ? a(
                                        "div",
                                        { staticClass: "tower-game-menu__main__no-stage" },
                                        [a("a", { on: { click: function (t) { e.show = "no-stage"; } } }, [e._m(1)])]
                                      )
                                    : e._e(),
                                  e.maps && e.maps.length
                                    ? a(
                                        "ul",
                                        e._l(e.maps, function (t, s) {
                                          return a(
                                            "li",
                                            { key: "map-" + t.ident + "-" + s },
                                            [
                                              a(
                                                "button",
                                                {
                                                  staticClass: "tower-game-menu__map",
                                                  class: { unavailable: !t.available },
                                                  on: { click: function (a) { return e.selectMap(t); } },
                                                },
                                                [
                                                  a("div", { staticClass: "tower-game-menu__map__img" }, [
                                                    a("img", { attrs: { src: "/images/towergame/map_icons/" + t.ident + ".png", draggable: "false" } }),
                                                  ]),
                                                  a("div", { staticClass: "tower-game-menu__map__title" }, [
                                                    a("h3", [e._v(e._s(t.name))]),
                                                    a(
                                                      "p",
                                                      { staticClass: "tower-game-menu__map__title__description" },
                                                      [e._v(" " + e._s(t.description) + " ")]
                                                    ),
                                                    t.data && e.mapHasProgress(t.data)
                                                      ? a("div", { staticClass: "tower-game-menu__map__info" }, [
                                                          a("ul", [
                                                            a("li", [a("span", [e._v("Highest Score:")]), e._v(" "), a("span", [e._v(e._s(t.data.highScore.toLocaleString()))])]),
                                                            a("li", [a("span", [e._v("Highest Round:")]), e._v(" "), a("span", [e._v(e._s(t.data.maxCompletedRound + 1))])]),
                                                          ]),
                                                        ])
                                                      : e._e(),
                                                    e._m(2, !0),
                                                  ]),
                                                ]
                                              ),
                                            ]
                                          );
                                        })
                                      )
                                    : a("h2", { staticClass: "tower-game-menu__maps__loading" }, [a("span", [e._v("Loading...")])]),
                                ])
                              : e._e(),
                          ]),
                        ]
                      ),
                    ]),
                    a(
                      "div",
                      {
                        staticClass: "tower-game-menu__play",
                        class: { active: "title" === e.show },
                        on: { click: function (t) { e.sideMenuOpen = !1; } },
                      },
                      [
                        a(
                          "button",
                          { attrs: { title: "Play" }, on: { click: e.onPlayPressed } },
                          [a("img", { attrs: { src: "/images/playButton.png", draggable: "false" } })]
                        ),
                      ]
                    ),
                  ]),
                  e.showContinueCampaignModal && e.selectedMap && e.selectedMap.data && e.selectedMap.data.activeCampaign
                    ? a("div", { staticClass: "tower-game-menu__continue" })
                    : e._e(),
                  "no-stage" === e.show
                    ? a(
                        "div",
                        { staticClass: "tower-game-menu__no-stage tower-game-menu__modal" },
                        [
                          a("div", { staticClass: "tower-game-menu__modal-bg" }),
                          a("div", { staticClass: "tower-game-menu__modal__inner" }, [
                            a("h2", [e._v("Warning")]),
                            a("h3", [e._v("Mastery Zone data not available")]),
                            a("p", [e._v("Please complete one session of Mastery Zone before playing Bee Sieged")]),
                            a("div", { staticClass: "tower-game-menu__modal__actions" }, [
                              a("button", { staticClass: "tower-game-button", on: { click: e.conintueWithEphemeralGame } }, [a("span", [e._v("Continue Without Saving")])]),
                              a("button", { staticClass: "tower-game-button", on: { click: e.redirectToMiniDiagnostic } }, [a("span", [e._v("Play Mastery Zone")])]),
                            ]),
                          ]),
                        ]
                      )
                    : e._e(),
                  a("div", { attrs: { id: "sideMenu" } }, [a("SideBarMenu", { attrs: { location: "spelling" } })], 1),
                  a(
                    "a",
                    {
                      staticClass: "navbar-burger",
                      class: { "is-active": e.sideMenuOpen },
                      on: {
                        click: function (t) {
                          t.preventDefault();
                          e.sideMenuOpen = !e.sideMenuOpen;
                        },
                      },
                    },
                    [a("span"), a("span"), a("span")]
                  ),
                  a("div", { staticClass: "font-preload" }, [e._v(" font ")]),
                ]
              )
            : e._e();
        },
        i = [
          function () {
            var e = this,
              t = e.$createElement,
              a = e._self._c || t;
            return a("div", { staticClass: "tower-game-menu__logo" }, [a("img", { attrs: { src: "/images/towergame/beesieged_logo.png", draggable: "false" } })]);
          },
          function () {
            var e = this,
              t = e.$createElement,
              a = e._self._c || t;
            return a("span", [a("i", { staticClass: "mdi mdi-alert" }), e._v(" Game data, score and honeypot earnings will not be saved")]);
          },
          function () {
            var e = this,
              t = e.$createElement,
              a = e._self._c || t;
            return a("div", { staticClass: "tower-game-menu__map__play" }, [a("img", { attrs: { src: "/images/playButton.png", draggable: "false" } })]);
          },
        ],
        n = a(41034),
        o = a(91114),
        r = (a(89463), a(16280), a(44114), a(18111), a(20116), a(61701), a(27495), a(25440), a(62953), a(31635)),
        l = a(18657),
        c = a(7411),
        m = a(52218),
        u = a(27021),
        p = a(7504),
        h = a(191);

      let d =
        class extends (0, l.Xe)() {
          constructor(...e) {
            super(...e),
              (0, o.A)(this, "show", "title"),
              (0, o.A)(this, "firstPlay", !1),
              (0, o.A)(this, "needsToDoMiniDiagnostic", !1),
              (0, o.A)(this, "maps", []),
              (0, o.A)(this, "selectedMap", null),
              (0, o.A)(this, "showContinueCampaignModal", !1),
              (0, o.A)(this, "sideMenuOpen", !1),
              (0, o.A)(this, "initialised", !1);
          }

          get showMainMenu() {
            return "map" === this.show;
          }

          get canPlayAdaptive() {
            if (!this.$store.state.user || !this.$store.state.user.school) return !1;
            const e = this.$store.state.user,
              t = this.$store.state.user.school;
            return !!(0, h.Cf)(t) && (("full" === e.spelling_access_level || "trial" === e.spelling_access_level) && !this.$store.getters.hasLimitLists);
          }

          async created() {
            this.canPlayAdaptive
              ? (this.$route.params && this.$route.params.navigatedFromGame && (this.show = "map"), this.$route.query.firstPlay && ((this.firstPlay = !0), this.$router.replace({})), await this.getAdaptiveProgress(), await this.loadMaps(), this.$sounds.backgroundMusic.stop(), (this.initialised = !0))
              : this.$router.push({ name: "SpellingMenu" });
          }

          mounted() {
            document.documentElement.setAttribute("theme", "");
          }

          get locale() {
            return (this.$store.state.user && this.$store.state.user.voice_locale) || "en_GB";
          }

          async getAdaptiveProgress() {
            if (this.$store.state.user)
              try {
                const e = await u.jIY.getMyAdaptiveSpellingProgress(),
                  t = null !== e.currentStage;
                if (!t) return (this.firstPlay = !0), (this.needsToDoMiniDiagnostic = !0), !1;
              } catch (e) {
                return (this.firstPlay = !0), (this.needsToDoMiniDiagnostic = !0), !1;
              }
          }

          onPlayPressed() {
            this.needsToDoMiniDiagnostic ? (this.show = "no-stage") : (this.show = "map");
          }

          selectMap(e) {
            this.selectedMap = e;
            this.transitionToGame(e.ident);
          }

          promptContinueCampaign() {
            this.showContinueCampaignModal = !0;
          }

          startNewMapCampaign() {
            this.selectedMap && this.transitionToGame(this.selectedMap.ident);
          }

          cancelContinueCampaign() {
            (this.selectedMap = null), (this.showContinueCampaignModal = !1);
          }

          continueSelectedMapCampaign() {
            if (!this.selectedMap) return;
            const e = "";
            this.selectedMap.data && this.selectedMap.data.activeCampaign;
            this.transitionToGame(this.selectedMap.ident, e);
          }

          conintueWithEphemeralGame() {
            this.show = "map";
          }

          async redirectToMiniDiagnostic() {
            try {
              const e = await u.jIY.createMiniDiagnosticGameSession(),
                t = (0, n.A)((0, n.A)({}, e), {}, { words: [e.currentWordData.text], wordsData: [e.currentWordData], gameType: "adaptive spelling mini-diagnostic", list: "", difficulty: 4 }),
                a = this.locale ? this.locale.split("_").join("-").toLowerCase() : "en-gb",
                s = { session: t, theme: "spelling", adaptive: !0, returnURL: `${p.A.serverInfo.game}${a}/beesieged` };
              this.$router.push({ name: "SpellingGame", params: s });
            } catch (e) {
              e instanceof Error && (console.error(e), this.$router.push({ name: "MainMenu" }));
            }
          }

          transitionToGame(e, t = "") {
            const a = this.maps.find((t) => t.ident === e);
            if (!a) return;
            const s = a.data;
            if (!s) return;
            (this.showContinueCampaignModal = !1), (this.show = "begin");
            const i = { map: e, campaign_id: t, isEphemeralGame: this.needsToDoMiniDiagnostic, maxRound: s.maxCompletedRound, maxScore: s.highScore };
            setTimeout(() => {
              this.$router.push({ name: "Bee Sieged Game", query: { firstPlay: this.firstPlay ? "true" : void 0 }, params: i });
            }, 600);
          }

          returnToMenu() {
            this.$router.push({ name: "SpellingMenu" });
          }

          mapHasProgress(e) {
            return e.highScore > 0 || e.maxCompletedRound > 0;
          }

          async loadMaps() {
            let e = null;
            try {
              e = await u.jIY.getTowerSpellingGameProgress();
            } catch (a) {
              a instanceof Error && console.error("Cannot get progress", a);
            }
            const t = Object.values(c.A);
            this.maps = t.map((t) => {
              const a = e ? e[t.key] : void 0;
              return { ident: t.key, name: t.name, description: t.description, available: !this.firstPlay || "beehive" === t.key, data: a };
            });
          }
        };

      d = (0, r.Cg)([(0, l.uA)({ components: { SideBarMenu: m.A } })], d);
      var g = d,
        _ = g,
        v = a(81656),
        w = (0, v.A)(_, s, i, !1, null, "660f4697", null),
        y = w.exports;
    },
  },
]);

//# sourceMappingURL=6487.674f9e28.js.map
